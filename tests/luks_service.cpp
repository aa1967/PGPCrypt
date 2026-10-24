// Isolated D-Bus integration checks: this executable never talks to system UDisks.
#include "../desktop/luks.h"
#include <QApplication>
#include <QDBusMetaType>
#include <QDBusVirtualObject>
#include <QEventLoop>
#include <QTemporaryDir>
#include <cstdio>
#include <cstdlib>

static void require(bool condition, const char* explanation) {
    if(!condition) {std::fprintf(stderr,"LUKS check failed: %s\n",explanation); std::exit(1);}
}
static QString await(const std::function<void(Luks::Completion)>& start) {
    QEventLoop loop; QString result="Test timed out"; bool done=false;
    QTimer deadline; deadline.setSingleShot(true); QObject::connect(&deadline,&QTimer::timeout,&loop,&QEventLoop::quit); deadline.start(10000);
    start([&](const QString& error) {result=error;done=true;loop.quit();});
    if(!done) loop.exec();
    return result;
}

class FakeDisks final : public QDBusVirtualObject {
public:
    const QString loop=Luks::Root+"/block_devices/loop0", fresh=Luks::Root+"/block_devices/loop1";
    const QString clear=Luks::Root+"/block_devices/dm_0", system=Luks::Root+"/block_devices/sda1";
    Luks::Objects objects;
    QStringList operations;
    bool busy=false, failLock=false, mounted=false, wrongKey=false;
    int attachments=0, formats=0;
    QVariantMap mountOptions, formatOptions;
    QString introspect(const QString&) const override {return {};}
    void setMounted(bool value) {
        mounted=value;
        objects[QDBusObjectPath(clear)][Luks::Filesystem]["MountPoints"]=QVariant::fromValue(value?QList<QByteArray>{QByteArray("/test/mount\0",12)}:QList<QByteArray>{});
    }
    explicit FakeDisks(const QString& backing) {
        objects[QDBusObjectPath(loop)]={
            {Luks::Block,{{"HintSystem",false},{"IdType","crypto_LUKS"},{"IdUsage","crypto"},{"ReadOnly",false},{"PreferredDevice",QByteArray("/dev/loop0")}}},
            {Luks::Loop,{{"SetupByUID",static_cast<uint>(::getuid())},{"BackingFile",QFile::encodeName(backing)}}},
            {Luks::Encrypted,{{"CleartextDevice",QVariant::fromValue(QDBusObjectPath("/"))}}}};
        objects[QDBusObjectPath(clear)]={{Luks::Block,{{"ReadOnly",false}}},{Luks::Filesystem,{}}};
        objects[QDBusObjectPath(system)]={{Luks::Block,{{"HintSystem",true},{"IdType","crypto_LUKS"}}},{Luks::Encrypted,{}}};
        setMounted(false);
    }
    bool handleMessage(const QDBusMessage& message,const QDBusConnection& connection) override {
        const auto name=message.member(); operations.append(name);
        const auto ok=[&](const QVariantList& args=QVariantList{}) {connection.send(message.createReply(args));};
        const auto fail=[&](const QString& code) {connection.send(message.createErrorReply("org.freedesktop.UDisks2.Error."+code,"Deliberately hidden daemon text"));};
        if(name=="GetManagedObjects") {ok({QVariant::fromValue(objects)}); return true;}
        if(name=="LoopSetup") {
            ++attachments;
            const auto fd=qvariant_cast<QDBusUnixFileDescriptor>(message.arguments().at(0)); struct stat info{};
            require(fd.isValid() && ::fstat(fd.fileDescriptor(),&info)==0 && S_ISREG(info.st_mode),"loop receives a real regular-file descriptor");
            const auto options=qdbus_cast<QVariantMap>(message.arguments().at(1));
            require(options.value("no-part-scan").toBool(),"no automatic partition scan");
            objects[QDBusObjectPath(fresh)]={{Luks::Block,{{"HintSystem",false},{"IdUsage",""},{"PreferredDevice",QByteArray("/dev/loop1")}}},{Luks::Loop,{{"SetupByUID",static_cast<uint>(::getuid())},{"BackingFile",QByteArray("/unused/new-container")}}}};
            ok({QVariant::fromValue(QDBusObjectPath(fresh))}); return true;
        }
        if(name=="Unlock") {
            const auto options=qdbus_cast<QVariantMap>(message.arguments().at(1));
            require(message.arguments().at(0).toString().isEmpty(),"no password string argument");
            require(options.value("keyfile_contents").metaType().id()==QMetaType::QByteArray,"password is binary IPC data");
            if(wrongKey || options.value("keyfile_contents").toByteArray()!=QByteArray("test key")) {fail("Failed"); return true;}
            objects[QDBusObjectPath(message.path())][Luks::Encrypted]["CleartextDevice"]=QVariant::fromValue(QDBusObjectPath(clear));
            ok({QVariant::fromValue(QDBusObjectPath(clear))}); return true;
        }
        if(name=="Mount") {
            mountOptions=qdbus_cast<QVariantMap>(message.arguments().first()); setMounted(true); ok({QString("/test/mount")}); return true;
        }
        if(name=="Unmount") {if(busy) fail("DeviceBusy"); else {setMounted(false);ok();} return true;}
        if(name=="Lock") {
            if(failLock) {fail("Failed");return true;}
            require(!mounted,"unmount completes before lock");
            objects[QDBusObjectPath(message.path())][Luks::Encrypted]["CleartextDevice"]=QVariant::fromValue(QDBusObjectPath("/")); ok();return true;
        }
        if(name=="Delete") {require(!mounted,"no detach of a mounted volume");ok();return true;}
        if(name=="Format") {
            ++formats; require(message.path()==fresh,"only freshly created loop can be formatted");
            require(message.arguments().first().toString()=="ext4","standard ext4 filesystem");
            formatOptions=qdbus_cast<QVariantMap>(message.arguments().at(1));
            require(formatOptions.value("encrypt.type").toString()=="luks2" && formatOptions.value("take-ownership").toBool(),"LUKS2 and caller ownership requested");
            require(formatOptions.value("encrypt.passphrase").metaType().id()==QMetaType::QByteArray,"format key sent as binary IPC data");
            objects[QDBusObjectPath(fresh)][Luks::Block]["IdType"]="crypto_LUKS";
            objects[QDBusObjectPath(fresh)][Luks::Block]["IdUsage"]="crypto";
            objects[QDBusObjectPath(fresh)][Luks::Encrypted]["CleartextDevice"]=QVariant::fromValue(QDBusObjectPath(clear));ok();return true;
        }
        fail("UnknownMethod"); return true;
    }
};

int main(int argc,char** argv) {
    QApplication app(argc,argv); qDBusRegisterMetaType<Luks::Interfaces>(); qDBusRegisterMetaType<Luks::Objects>();
    QTemporaryDir temporary; require(temporary.isValid(),"private test directory");
    QString error;
    const auto filename=temporary.filePath("source.luks");
    auto existing=Luks::openFile(filename,true,false,error); require(existing!=nullptr,"exclusive creation");
    auto overwrite=Luks::openFile(filename,true,false,error);require(!overwrite,"refuse existing destination");
    const auto alias=temporary.filePath("alias");require(::symlink(QFile::encodeName(filename).constData(),QFile::encodeName(alias).constData())==0,"symlink fixture");
    require(!Luks::openFile(alias,false,false,error),"refuse final symlink");
    require(!Luks::openFile(temporary.path(),false,true,error),"refuse directory");
    struct stat info{}; require(::fstat(existing->fd,&info)==0 && (info.st_mode&0777)==0600,"private file permissions");
    auto server=QDBusConnection::sessionBus(); require(server.isConnected(),"private session bus");
    FakeDisks fake(filename);
    require(server.registerService("org.pgpcrypt.TestDisks"),"register fake service");
    require(server.registerVirtualObject(Luks::Root,&fake,QDBusConnection::SubPath),"export fake objects");
    const auto client=QDBusConnection::connectToBus(QDBusConnection::SessionBus,"luks-test-client");
    Luks::Service service(&app,client,"org.pgpcrypt.TestDisks");
    require(await([&](auto done) {service.refresh(done);}).isEmpty(),"read typed device map");
    require(!Luks::selectable(service.objects.value(QDBusObjectPath(fake.system))),"exclude system volume");
    require(await([&](auto done) {service.mount(fake.system,{},false,done);}).contains("non-system"),"system mount rejected");
    require(await([&](auto done) {service.formatNew(existing,{},done);}).contains("newly"),"unallocated file cannot be formatted");
    auto reopened=Luks::openFile(filename,false,false,error); require(reopened!=nullptr,"open existing file");
    require(await([&](auto done) {service.formatNew(reopened,{},done);}).contains("newly"),"existing file cannot be formatted");
    QString attached;
    require(await([&](auto done) {service.attach(reopened,false,[&](const QString& path,const QString& issue) {attached=path;done(issue);});}).isEmpty() && attached==fake.loop && fake.attachments==0,"reuse existing same-inode loop");
    require(await([&](auto done) {service.mount(fake.loop,"test key",true,done);}).isEmpty(),"unlock and mount existing container");
    require(fake.mountOptions.value("options").toString()=="ro,nosuid,nodev,noexec","read-only and restrictive mount flags");
    require(!await([&](auto done) {service.mount(fake.loop,{},true,done);}).isEmpty(),"do not claim read-only applied to existing writable device");
    fake.busy=true; fake.operations.clear();
    require(await([&](auto done) {service.closeVolume(fake.loop,done);}).contains("busy"),"busy unmount is reported");
    require(!fake.operations.contains("Lock") && !fake.operations.contains("Delete"),"busy failure never locks or detaches");
    fake.busy=false; fake.failLock=true; fake.operations.clear();
    require(!await([&](auto done) {service.closeVolume(fake.loop,done);}).isEmpty() && !fake.operations.contains("Delete"),"failed lock never detaches");
    fake.failLock=false; fake.operations.clear();
    require(await([&](auto done) {service.closeVolume(fake.loop,done);}).isEmpty(),"lock confirmed before detach");
    require(fake.operations.indexOf("Lock")<fake.operations.indexOf("Delete"),"lock/detach ordering");
    fake.wrongKey=true; fake.operations.clear();
    require(!await([&](auto done) {service.mount(fake.loop,"wrong",false,done);}).isEmpty() && !fake.operations.contains("Mount"),"wrong password never mounts");
    fake.wrongKey=false;
    const auto fresh=Luks::openFile(temporary.filePath("new.luks"),true,false,error); require(fresh!=nullptr,"new-container reservation");
    const auto cancelled=std::make_shared<std::atomic_bool>(true);
    require(Luks::fillFile(fresh,64*1024*1024,cancelled,[](int){}).contains("cancelled"),"cancel allocation before format");
    cancelled->store(false);
    require(Luks::fillFile(fresh,64*1024*1024,cancelled,[](int){}).isEmpty(),"fully allocate with system randomness");
    require(::fstat(fresh->fd,&info)==0 && info.st_size==64*1024*1024 && info.st_blocks*512>=info.st_size,"no sparse allocation");
    require(await([&](auto done) {service.formatNew(fresh,"new password",done);}).isEmpty() && fake.formats==1,"format only the new reserved file");
    require(await([&](auto done) {service.formatNew(fresh,{},done);}).contains("newly") && fake.formats==1,"do not repeat submitted formatting");
    auto* panel=Luks::panel(nullptr); require(panel->findChildren<QPushButton*>().size()==3,"three landing controls");
    const auto help=panel->findChildren<QToolButton*>(); require(help.size()==1 && help.first()->toolTip().contains("separate") && help.first()->focusPolicy()!=Qt::NoFocus,"hover/click/keyboard help"); delete panel;
    std::puts("LUKS private-bus checks passed: file safety, descriptor credentials, slot-independent mounting, failure handling and close ordering; no real disks used.");
}
