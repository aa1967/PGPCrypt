#pragma once

// Optional disk utility. UDisks owns cryptsetup/device-mapper privileges; the GUI
// never invokes a shell, sudo, or a general-purpose privileged project helper.
#include "context_help.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusUnixFileDescriptor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPointer>
#include <QSet>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zxcvbn.h>

namespace Luks {
inline const QString Root = "/org/freedesktop/UDisks2";
inline const QString Block = "org.freedesktop.UDisks2.Block";
inline const QString Encrypted = "org.freedesktop.UDisks2.Encrypted";
inline const QString Filesystem = "org.freedesktop.UDisks2.Filesystem";
inline const QString Loop = "org.freedesktop.UDisks2.Loop";
using Interfaces = QMap<QString, QVariantMap>;
using Objects = QMap<QDBusObjectPath, Interfaces>;
using Completion = std::function<void(const QString&)>;

inline QString pathValue(const QVariant& value) {
    return qvariant_cast<QDBusObjectPath>(value).path();
}
inline QString bytePath(const QVariant& value) {
    auto bytes = value.toByteArray();
    if(bytes.endsWith('\0')) bytes.chop(1);
    return QFile::decodeName(bytes);
}
inline QStringList mounts(const Interfaces& object) {
    QStringList result;
    const auto value = object.value(Filesystem).value("MountPoints");
    const auto paths = qdbus_cast<QList<QByteArray>>(value);
    for(const auto& path:paths) result.append(bytePath(path));
    return result;
}
inline QString description(const Interfaces& object) {
    auto result = bytePath(object.value(Block).value("PreferredDevice"));
    const auto backing = bytePath(object.value(Loop).value("BackingFile"));
    if(!backing.isEmpty()) result += " — " + backing;
    return result;
}
inline bool selectable(const Interfaces& object, bool includeInternal = false) {
    const auto block = object.value(Block);
    // UDisks conservatively marks loop devices as system devices too. A loop
    // created by this user is not an operating-system disk merely for that reason.
    if(object.contains(Loop) && object.value(Loop).contains("SetupByUID")
       && object.value(Loop).value("SetupByUID").toUInt() == ::getuid()) return true;
    if(!block.contains("HintSystem") || (block.value("HintSystem").toBool() && !includeInternal)) return false;
    return block.value("IdType").toString() == "crypto_LUKS";
}

struct File final {
    int fd = -1;
    int directory = -1;
    bool fresh = false;
    qint64 bytes = 0;
    ~File() {if(fd >= 0) ::close(fd); if(directory >= 0) ::close(directory);}
    File() = default;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};

// A descriptor, not a path, is passed to the privileged service. Exclusive
// creation and O_NOFOLLOW prevent truncating an existing file or a symlink.
inline std::shared_ptr<File> openFile(const QString& filename, bool create, bool readOnly, QString& error) {
    const auto encoded = QFile::encodeName(QFileInfo(filename).absoluteFilePath());
    auto file = std::make_shared<File>();
    const auto flags = (readOnly ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY;
    if(create) {
        const auto parent=QFile::encodeName(QFileInfo(filename).absolutePath());
        const auto name=QFile::encodeName(QFileInfo(filename).fileName());
        file->directory=::open(parent.constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(file->directory>=0) file->fd=::openat(file->directory,name.constData(),flags|O_CREAT|O_EXCL,0600);
    } else file->fd=::open(encoded.constData(),flags);
    struct stat info{};
    if(file->fd < 0 || ::fstat(file->fd, &info) != 0 || !S_ISREG(info.st_mode)
       || (create && (info.st_uid != ::getuid() || info.st_nlink != 1 || (info.st_mode & 0777) != 0600))) {
        error = "Choose a readable regular container file; creation requires a new filename in a writable folder. Symlinks and devices are not accepted here.";
        return {};
    }
    file->fresh = create;
    return file;
}

inline QString fillFile(const std::shared_ptr<File>& file, qint64 bytes,
                        const std::shared_ptr<std::atomic_bool>& cancelled,
                        const std::function<void(int)>& progress) {
    if(!file || !file->fresh || bytes < 1024 * 1024) return "Invalid new-container reservation.";
    QByteArray buffer(1024 * 1024, '\0');
    for(qint64 offset = 0; offset < bytes;) {
        if(cancelled->load()) return "Creation cancelled. The incomplete file has been left in place; remove it before trying that filename again.";
        const auto count = static_cast<qsizetype>(qMin<qint64>(buffer.size(), bytes-offset));
        for(qsizetype obtained = 0; obtained < count;) {
            const auto n = ::getrandom(buffer.data()+obtained, static_cast<size_t>(count-obtained), 0);
            if(n < 0 && errno == EINTR) continue;
            if(n <= 0) return "System randomness is unavailable. An incomplete file has been left in place.";
            obtained += n;
        }
        for(qsizetype written = 0; written < count;) {
            const auto n = ::pwrite(file->fd, buffer.constData()+written, static_cast<size_t>(count-written), offset+written);
            if(n < 0 && errno == EINTR) continue;
            if(n <= 0) return "Could not allocate the container. Check free space and permissions; an incomplete file has been left in place.";
            written += n;
        }
        offset += count;
        progress(static_cast<int>(offset * 100 / bytes));
    }
    if(::fsync(file->fd) != 0 || (file->directory>=0 && ::fsync(file->directory)!=0)) return "Container synchronization failed. Creation has stopped; the incomplete file remains.";
    file->bytes = bytes;
    return {};
}

class Service final : public QObject {
    QDBusConnection bus;
    QString destination;
public:
    Objects objects;
    bool includeInternal = false;
    // Connection injection is for the isolated fake-service test. Production
    // always uses the system bus and the well-known UDisks service name.
    explicit Service(QObject* parent, QDBusConnection connection = QDBusConnection::systemBus(),
                     QString name = "org.freedesktop.UDisks2")
        : QObject(parent), bus(std::move(connection)), destination(std::move(name)) {
        qDBusRegisterMetaType<QList<QByteArray>>();
        qDBusRegisterMetaType<Interfaces>();
        qDBusRegisterMetaType<Objects>();
    }

    void call(const QString& path, const QString& interface, const QString& method,
              const QVariantList& args, std::function<void(const QDBusMessage&)> completed) {
        auto message = QDBusMessage::createMethodCall(destination, path, interface, method);
        message.setArguments(args);
        message.setInteractiveAuthorizationAllowed(true);
        auto* watcher = new QDBusPendingCallWatcher(bus.asyncCall(message, 300000), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [watcher, completed](QDBusPendingCallWatcher*) {
            const auto reply = watcher->reply(); watcher->deleteLater(); completed(reply);
        });
    }

    static QString failure(const QDBusMessage& reply) {
        if(reply.type() != QDBusMessage::ErrorMessage) return {};
        const auto name = reply.errorName();
        if(name.contains("NotAuthorized") || name.contains("AuthFailed"))
            return "Authorization was denied or cancelled. A desktop polkit authentication agent may be required.";
        if(name.contains("ServiceUnknown") || name.contains("NameHasNoOwner") || name.contains("Disconnected") || name.contains("FileNotFound"))
            return "UDisks is unavailable. Install udisks2, cryptsetup-bin, e2fsprogs and a desktop polkit agent in this Debian guest, then retry.";
        if(name.contains("DeviceBusy")) return "The volume is busy. Close files, terminals and file-manager windows using it, then retry. It remains unlocked.";
        if(name.contains("NoReply") || name.contains("Timeout"))
            return "The disk service did not confirm completion. The operation may still be running; refresh the volume list before retrying.";
        // Never surface the daemon's arbitrary error body: it could contain
        // credentials supplied to an external formatting helper.
        return "The disk operation failed. Check the password, permissions, filesystem support and free space. Refresh to check whether the volume remains unlocked.";
    }

    void refresh(Completion completed) {
        call(Root, "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", {}, [this, completed](const QDBusMessage& reply) {
            const auto error = failure(reply);
            if(!error.isEmpty()) {completed(error); return;}
            if(reply.arguments().size() != 1) {completed("The disk service returned an invalid device list."); return;}
            objects = qdbus_cast<Objects>(reply.arguments().first()); completed({});
        });
    }

    bool allowed(const QString& path) const {
        if(!selectable(objects.value(QDBusObjectPath(path)),includeInternal)) return false;
        QSet<QString> children{path};
        for(int pass=0;pass<32;++pass) {
            const auto before=children.size();
            for(auto it=objects.cbegin();it!=objects.cend();++it) {
                const auto parent=pathValue(it.value().value(Block).value("CryptoBackingDevice"));
                const auto table=pathValue(it.value().value("org.freedesktop.UDisks2.Partition").value("Table"));
                if(children.contains(parent) || children.contains(table)) children.insert(it.key().path());
                if(children.contains(it.key().path())) {
                    const auto clear=pathValue(it.value().value(Encrypted).value("CleartextDevice"));
                    if(!clear.isEmpty() && clear!="/") children.insert(clear);
                }
            }
            if(before==children.size()) break;
            if(pass==31) return false;
        }
        const QSet<QString> protectedMounts{"/","/boot","/boot/efi","/usr","/var","/home","/run","/etc","/bin","/lib","/lib64","/sbin","/tmp"};
        for(const auto& child:children) {
            const auto object=objects.value(QDBusObjectPath(child));
            if(object.value("org.freedesktop.UDisks2.Swapspace").value("Active").toBool()) return false;
            for(const auto& folder:mounts(object)) if(protectedMounts.contains(folder)) return false;
        }
        return true;
    }

    void attach(const std::shared_ptr<File>& file, bool readOnly, std::function<void(QString,QString)> completed) {
        refresh([this,file,readOnly,completed](const QString& error) {
            if(!error.isEmpty()) {completed({},error); return;}
            attachCurrent(file,readOnly,completed);
        });
    }

    void attachCurrent(const std::shared_ptr<File>& file, bool readOnly, std::function<void(QString,QString)> completed) {
        if(!file || file->fd < 0) {completed({}, "No container file is open."); return;}
        struct stat sourceInfo{};
        if(::fstat(file->fd,&sourceInfo) != 0) {completed({},"The container file cannot be inspected."); return;}
        for(auto it=objects.cbegin();it!=objects.cend();++it) {
            if(!it.value().contains(Loop)) continue;
            const auto backing=QFile::encodeName(bytePath(it.value().value(Loop).value("BackingFile")));
            struct stat attachedInfo{};
            if(::stat(backing.constData(),&attachedInfo)!=0 || sourceInfo.st_ino!=attachedInfo.st_ino || sourceInfo.st_dev!=attachedInfo.st_dev) continue;
            if(file->fresh) {completed({},"This file is already attached; formatting has been refused."); return;}
            if(it.value().value(Loop).value("SetupByUID").toUInt()!=::getuid()) {completed({},"This container is already attached by another user. Use its existing mount or ask that user to close it."); return;}
            if(!readOnly && it.value().value(Block).value("ReadOnly").toBool()) {completed({},"This container is already attached read-only. Unmount and lock it before opening for writing."); return;}
            completed(it.key().path(),{}); return;
        }
        QVariantMap options{{"read-only",readOnly},{"no-part-scan",true}};
        call(Root+"/Manager", "org.freedesktop.UDisks2.Manager", "LoopSetup",
             {QVariant::fromValue(QDBusUnixFileDescriptor(file->fd)),options},
             [this,file,completed](const QDBusMessage& reply) {
            const auto error = failure(reply);
            if(!error.isEmpty()) {completed({},error); return;}
            const auto path = reply.arguments().isEmpty() ? QString() : pathValue(reply.arguments().first());
            if(!path.startsWith(Root+"/block_devices/")) {completed({},"The disk service returned an invalid loop device."); return;}
            refresh([path,completed](const QString& problem) {completed(path,problem);});
        });
    }

    void mount(const QString& encrypted, QByteArray password, bool readOnly, Completion completed) {
        refresh([this,encrypted,password,readOnly,completed](const QString& error) mutable {
            if(!error.isEmpty()) {password.fill('\0'); completed(error); return;}
            mountCurrent(encrypted,password,readOnly,completed); password.fill('\0');
        });
        password.fill('\0');
    }

    void mountCurrent(const QString& encrypted, QByteArray password, bool readOnly, Completion completed) {
        const auto object = objects.value(QDBusObjectPath(encrypted));
        if(!allowed(encrypted) || object.value(Block).value("IdType").toString() != "crypto_LUKS") {
            password.fill('\0'); completed("Select a non-system LUKS volume. This utility does not format existing drives."); return;
        }
        const auto clear = pathValue(object.value(Encrypted).value("CleartextDevice"));
        if(!clear.isEmpty() && clear != "/") {password.fill('\0'); mountClear(clear, readOnly, completed); return;}
        // Byte-array credentials support an empty password without telling
        // UDisks to look for a password in /etc/crypttab.
        QVariantMap options{{"keyfile_contents",password},{"read-only",readOnly}};
        call(encrypted, Encrypted, "Unlock", {QString(),options}, [this, readOnly, completed](const QDBusMessage& reply) {
            const auto error = failure(reply);
            if(!error.isEmpty()) {completed(error); return;}
            const auto clear = reply.arguments().isEmpty() ? QString() : pathValue(reply.arguments().first());
            if(!clear.startsWith(Root+"/block_devices/")) {completed("No decrypted device was returned. Refresh the volume list."); return;}
            refresh([this,clear,readOnly,completed](const QString& problem) {
                if(!problem.isEmpty()) {completed(problem); return;}
                mountClear(clear,readOnly,completed);
            });
        });
        password.fill('\0');
    }

    void mountClear(const QString& clear, bool readOnly, Completion completed) {
        const auto object = objects.value(QDBusObjectPath(clear));
        if(!mounts(object).isEmpty()) {
            if(readOnly && !object.value(Block).value("ReadOnly").toBool()) {completed("The volume is already mounted. Read-only mode has not been applied; unmount and lock it first."); return;}
            completed({}); return;
        }
        if(!object.contains(Filesystem)) {completed("The unlocked volume has no directly mountable filesystem. Partitioned inner volumes need an external disk tool; the volume remains unlocked."); return;}
        QVariantMap options{{"options",QString(readOnly?"ro,":"")+"nosuid,nodev,noexec"}};
        call(clear, Filesystem, "Mount", {options}, [completed](const QDBusMessage& reply) {completed(failure(reply));});
    }

    void formatNew(const std::shared_ptr<File>& file, QByteArray password, Completion completed) {
        struct stat info{};
        if(!file || !file->fresh || file->bytes < 64 * 1024 * 1024 || ::fstat(file->fd,&info) != 0
           || !S_ISREG(info.st_mode) || info.st_size != file->bytes || info.st_uid != ::getuid()
           || info.st_nlink != 1 || (info.st_mode & 0777) != 0600) {
            password.fill('\0'); completed("Only a newly created, fully allocated private container file can be formatted."); return;
        }
        attach(file,false,[this,file,password,completed](const QString& path,const QString& error) mutable {
            if(!error.isEmpty()) {password.fill('\0'); completed(error); return;}
            const auto object = objects.value(QDBusObjectPath(path));
            if(!object.contains(Loop) || object.value(Loop).value("SetupByUID").toUInt() != ::getuid()
               || !object.value(Block).value("IdUsage").toString().isEmpty()) {
                password.fill('\0'); completed("The new loop device could not be safely identified; it was not formatted."); return;
            }
            file->fresh=false; // A submitted format may commit even if its reply is lost.
            QVariantMap options{{"encrypt.type","luks2"},{"encrypt.passphrase",password},{"take-ownership",true}};
            call(path,Block,"Format",{"ext4",options},[this,completed](const QDBusMessage& reply) {
                const auto problem = failure(reply);
                if(!problem.isEmpty()) {completed(problem); return;}
                refresh(completed);
            });
            password.fill('\0');
        });
        password.fill('\0');
    }

    void closeVolume(const QString& path, Completion completed) {
        refresh([this,path,completed](const QString& error) {
            if(!error.isEmpty()) {completed(error); return;}
            const auto object = objects.value(QDBusObjectPath(path));
            if(!allowed(path)) {completed("Select an allowed LUKS volume or a container loop owned by your user. Active operating-system volumes cannot be closed here."); return;}
            if(!object.contains(Encrypted)) {
                if(!mounts(object).isEmpty()) {completed("This is not a LUKS volume. Unmount it in your file manager before detaching its loop device."); return;}
                detach(path,completed); return;
            }
            const auto clear = pathValue(object.value(Encrypted).value("CleartextDevice"));
            if(clear.isEmpty() || clear == "/") {detach(path,completed); return;}
            const auto lock = [this,path,completed](const QString& problem) {
                if(!problem.isEmpty()) {completed(problem); return;}
                call(path,Encrypted,"Lock",{QVariantMap{}},[this,path,completed](const QDBusMessage& reply) {
                    const auto failed = failure(reply);
                    if(!failed.isEmpty()) {completed(failed); return;}
                    refresh([this,path,completed](const QString& issue) {
                        if(!issue.isEmpty()) {completed(issue); return;}
                        const auto clearNow = pathValue(objects.value(QDBusObjectPath(path)).value(Encrypted).value("CleartextDevice"));
                        if(!clearNow.isEmpty() && clearNow != "/") {completed("The volume still appears unlocked. Refresh and retry."); return;}
                        detach(path,completed);
                    });
                });
            };
            if(mounts(objects.value(QDBusObjectPath(clear))).isEmpty()) {lock({}); return;}
            call(clear,Filesystem,"Unmount",{QVariantMap{{"force",false}}},[lock](const QDBusMessage& reply) {lock(failure(reply));});
        });
    }

    void detach(const QString& path, Completion completed) {
        const auto object = objects.value(QDBusObjectPath(path));
        if(!object.contains(Loop) || object.value(Loop).value("SetupByUID").toUInt() != ::getuid()) {completed({}); return;}
        call(path,Loop,"Delete",{QVariantMap{}},[completed](const QDBusMessage& reply) {
            const auto error=failure(reply);
            completed(error.isEmpty()?QString():"Volume locked or unmounted, but its loop could not be detached. "+error);
        });
    }
};

inline const QString Help = "Optional outer encryption for drives and container files. Unlocking mounts a filesystem; it does not unlock a KDBX/age database inside it. Use Create vault or Open vault afterward. Database lock and LUKS lock are separate: use Unmount & lock to close a mounted volume. Mounts can survive app lock, exit or a crash. Passwords are sent to the system UDisks service over D-Bus, never command arguments. The OS and root can access mounted contents. No real/decoy/wipe routing is added to LUKS keyslots. In Qubes, run this inside the vault qube, never dom0.";

class Dialog final : public QDialog {
    Service service;
    QTabWidget* tabs;
    QLineEdit *source, *destination, *password, *confirmation;
    QComboBox *sourceType, *devices;
    QCheckBox *readOnly, *internal;
    QSpinBox* capacity;
    QTableWidget* volumes;
    QLabel *status, *strength;
    QProgressBar *progress, *strengthBar;
    QPushButton *run, *refreshButton, *cancelAllocation;
    QDialogButtonBox* buttons;
    bool busy = false;
    bool available = false;
    std::shared_ptr<std::atomic_bool> cancelled = std::make_shared<std::atomic_bool>(false);
    QPointer<QThread> allocator;

    void showStatus(const QString& text) {status->setText(text);}
    void setBusy(bool value) {
        busy=value; tabs->setEnabled(!value); run->setEnabled(!value && available);
        refreshButton->setEnabled(!value); buttons->setEnabled(!value); internal->setEnabled(!value);
        password->setEnabled(!value); confirmation->setEnabled(!value);
    }
    void populate() {
        const auto selected = devices->currentData(); devices->clear(); volumes->setRowCount(0);
        for(auto it=service.objects.cbegin();it!=service.objects.cend();++it) {
            const auto& object=it.value(); if(!service.allowed(it.key().path())) continue;
            const auto path=it.key().path(); const auto text=description(object);
            const bool encrypted=object.value(Block).value("IdType").toString()=="crypto_LUKS";
            if(encrypted) devices->addItem(text,path);
            const auto clear=pathValue(object.value(Encrypted).value("CleartextDevice"));
            auto folders=mounts(service.objects.value(QDBusObjectPath(clear.isEmpty()?"/":clear)));
            const auto row=volumes->rowCount(); volumes->insertRow(row);
            auto* item=new QTableWidgetItem(text); item->setData(Qt::UserRole,path); volumes->setItem(row,0,item);
            volumes->setItem(row,1,new QTableWidgetItem(!encrypted?"Container loop":clear.isEmpty() || clear=="/"?"Locked":folders.isEmpty()?"Unlocked; not mounted":"Mounted"));
            volumes->setItem(row,2,new QTableWidgetItem(folders.join(", ")));
        }
        const auto index=devices->findData(selected); if(index>=0) devices->setCurrentIndex(index);
        if(volumes->rowCount()) volumes->selectRow(0);
    }
    void refresh(bool announce = true) {
        setBusy(true);
        service.refresh([this,announce](const QString& error) {
            available=error.isEmpty(); if(available) populate();
            setBusy(false);
            if(!available) showStatus(error); else if(announce) showStatus("Ready. Database unlock and LUKS unlock are separate.");
        });
    }
    void finished(const QString& error, const QString& success) {
        showStatus(error.isEmpty()?success:error);
        service.refresh([this](const QString& issue) {available=issue.isEmpty(); if(available) populate(); else showStatus(issue); setBusy(false);});
    }
    void execute() {
        if(busy) return;
        if(tabs->currentIndex()==2) {
            const auto row=volumes->currentRow(); if(row<0) {showStatus("Select a volume first."); return;}
            const auto path=volumes->item(row,0)->data(Qt::UserRole).toString();
            setBusy(true); showStatus("Unmounting and locking…");
            service.closeVolume(path,[this](const QString& error) {finished(error,"Unmounted and locked; any loop owned by your user was detached.");}); return;
        }
        const bool create=tabs->currentIndex()==1;
        const auto filename=QFileInfo(create?destination->text():source->text()).absoluteFilePath();
        if((create?destination->text():source->text()).isEmpty() && (create || sourceType->currentIndex()==0)) {showStatus("Choose a container file."); return;}
        if(create && (password->text()!=confirmation->text() || password->text().toUcs4().size()>128)) {showStatus("Passwords must match and contain at most 128 characters."); return;}
        auto secret=password->text().toUtf8(); password->clear(); confirmation->clear();
        if(!create) {
            setBusy(true); showStatus("Unlocking and mounting…");
            const auto complete=[this](const QString& error) {finished(error,"Volume mounted. Check Mounts for its folder, then use Create vault or Open vault.");};
            if(sourceType->currentIndex()==1) {service.mount(devices->currentData().toString(),secret,readOnly->isChecked(),complete); secret.fill('\0'); return;}
            QString error; const auto file=openFile(filename,false,readOnly->isChecked(),error);
            if(!file) {secret.fill('\0'); setBusy(false); showStatus(error); return;}
            service.attach(file,readOnly->isChecked(),[this,secret,complete](const QString& path,const QString& issue) mutable {
                if(!issue.isEmpty()) {secret.fill('\0'); complete(issue); return;}
                service.mount(path,secret,readOnly->isChecked(),complete); secret.fill('\0');
            });
            secret.fill('\0'); return;
        }
        QString error; const auto file=openFile(filename,true,false,error);
        if(!file) {secret.fill('\0'); showStatus(error); return;}
        setBusy(true); showStatus("Allocating and randomizing the new container…"); progress->setValue(0); progress->show(); cancelAllocation->show(); cancelled->store(false);
        const auto bytes=static_cast<qint64>(capacity->value())*1024*1024;
        allocator=QThread::create([this,file,bytes,secret,filename]() mutable {
            const auto error=fillFile(file,bytes,cancelled,[this](int percent) {
                QMetaObject::invokeMethod(this,[this,percent] {progress->setValue(percent);},Qt::QueuedConnection);
            });
            QMetaObject::invokeMethod(this,[this,file,error,secret,filename]() mutable {
                progress->hide(); cancelAllocation->hide();
                if(!error.isEmpty()) {secret.fill('\0'); setBusy(false); showStatus(error); return;}
                showStatus("Creating LUKS2 and an ext4 filesystem…");
                service.formatNew(file,secret,[this,filename](const QString& issue) {
                    if(issue.isEmpty()) {sourceType->setCurrentIndex(0); source->setText(filename); tabs->setCurrentIndex(0);}
                    finished(issue,"LUKS2 container created. Unlock & mount will mount it; if already unlocked no password is needed.");
                });
                secret.fill('\0');
            },Qt::QueuedConnection);
            secret.fill('\0');
        });
        connect(allocator,&QThread::finished,allocator,&QObject::deleteLater); allocator->start();
        secret.fill('\0');
    }
public:
    explicit Dialog(QWidget* parent, int initialTab = 0) : QDialog(parent), service(this) {
        setObjectName("luksDialog"); setWindowTitle("LUKS volumes"); resize(830,540);
        auto* layout=new QVBoxLayout(this);
        auto* heading=new QHBoxLayout; heading->addWidget(new QLabel("LUKS drives and containers")); heading->addWidget(contextHelp(this,Help)); heading->addStretch(); layout->addLayout(heading);
        auto* scopeRow=new QHBoxLayout; internal=new QCheckBox("Show internal LUKS drives"); scopeRow->addWidget(internal); scopeRow->addWidget(contextHelp(this,"UDisks labels many internal and Qubes virtual disks as system devices. Enable to include unused internal LUKS drives; the OS may request administrator authorization. Active volumes mounted at operating-system locations remain excluded. This never enables drive formatting. Container loops owned by your user are always included.")); scopeRow->addStretch(); layout->addLayout(scopeRow);
        connect(internal,&QCheckBox::toggled,this,[this](bool value) {service.includeInternal=value; if(!busy) refresh(false);});
        tabs=new QTabWidget; layout->addWidget(tabs);
        auto* open=new QWidget; auto* openForm=new QFormLayout(open);
        sourceType=new QComboBox; sourceType->addItems({"Container file","LUKS drive / partition"}); openForm->addRow("Source",sourceType);
        auto* fileRow=new QHBoxLayout; source=new QLineEdit; auto* browse=new QPushButton("Browse…"); fileRow->addWidget(source); fileRow->addWidget(browse); openForm->addRow("Container",fileRow);
        devices=new QComboBox; openForm->addRow("LUKS volume",devices); devices->setEnabled(false);
        readOnly=new QCheckBox("Mount read-only"); openForm->addRow(readOnly);
        tabs->addTab(open,"Unlock & mount");
        auto* create=new QWidget; auto* createForm=new QFormLayout(create);
        auto* newRow=new QHBoxLayout; destination=new QLineEdit(QDir::home().filePath("vault.luks")); auto* choose=new QPushButton("Save as…"); newRow->addWidget(destination); newRow->addWidget(choose); createForm->addRow("New container",newRow);
        capacity=new QSpinBox; capacity->setRange(64,65536); capacity->setValue(256); capacity->setSuffix(" MiB"); createForm->addRow("Capacity",capacity);
        createForm->addRow("About creation",contextHelp(this,"Creates a new private file with a fixed capacity, fully fills it with system randomness, then creates standard LUKS2 and ext4 through UDisks/cryptsetup. Existing files and raw drives are never formatted. This can take time and requires the full amount of disk space. Failed or interrupted creation can leave an incomplete file. LUKS headers and file size remain identifiable; fixed capacity does not guarantee plausible deniability. Cryptsetup supplies the encryption/KDF defaults; no application crypto is invented."));
        tabs->addTab(create,"Create LUKS2 container");
        auto* manage=new QWidget; auto* manageLayout=new QVBoxLayout(manage);
        volumes=new QTableWidget(0,3); volumes->setHorizontalHeaderLabels({"Volume / container","State","Mounted folder"}); volumes->setEditTriggers(QAbstractItemView::NoEditTriggers); volumes->setSelectionBehavior(QAbstractItemView::SelectRows); volumes->setSelectionMode(QAbstractItemView::SingleSelection); volumes->verticalHeader()->hide(); volumes->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive); volumes->setColumnWidth(0,330); volumes->setColumnWidth(1,155); volumes->horizontalHeader()->setStretchLastSection(true); manageLayout->addWidget(volumes);
        manageLayout->addWidget(contextHelp(this,"Lists non-system LUKS volumes and container loops set up by your user, including volumes opened outside PGPCrypt. Nothing is recorded by PGPCrypt. Unmount & lock acts only on your selection and never forces a busy filesystem closed. Close applications using it before retrying. A locked container loop may also be detached. System volumes are excluded. After closing PGPCrypt or locking a database, mounted volumes stay mounted until explicitly closed here or with another disk tool."));
        tabs->addTab(manage,"Mounts"); tabs->setCurrentIndex(initialTab);
        auto* auth=new QFormLayout; password=new QLineEdit; password->setEchoMode(QLineEdit::Password); password->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText|Qt::ImhNoAutoUppercase); password->setMaxLength(32767); auth->addRow("Password/passphrase",password);
        confirmation=new QLineEdit; confirmation->setEchoMode(QLineEdit::Password); confirmation->setInputMethodHints(password->inputMethodHints()); confirmation->setMaxLength(256); auth->addRow("Confirm password/passphrase",confirmation); layout->addLayout(auth);
        strength=new QLabel; strength->setTextFormat(Qt::PlainText); layout->addWidget(strength); strengthBar=new QProgressBar; strengthBar->setRange(0,4); strengthBar->setTextVisible(false); strengthBar->setMaximumHeight(10); layout->addWidget(strengthBar);
        auto* strengthTimer=new QTimer(this); strengthTimer->setSingleShot(true); strengthTimer->setInterval(180);
        connect(password,&QLineEdit::textChanged,strengthTimer,qOverload<>(&QTimer::start));
        connect(strengthTimer,&QTimer::timeout,this,[this] {if(tabs->currentIndex()!=1) return; auto bytes=password->text().toUtf8(); const auto entropy=ZxcvbnMatch(bytes.constData(),nullptr,nullptr); bytes.fill('\0'); const int score=entropy<10?0:entropy<20?1:entropy<26.575?2:entropy<33.22?3:4; strengthBar->setValue(score); strength->setText("Estimated strength: "+QStringList{"Very weak","Weak","Fair","Good","Strong"}[score]);});
        status=new QLabel; status->setTextFormat(Qt::PlainText); status->setWordWrap(true); status->setTextInteractionFlags(Qt::TextSelectableByMouse|Qt::TextSelectableByKeyboard); layout->addWidget(status);
        progress=new QProgressBar; progress->hide(); layout->addWidget(progress);
        auto* actions=new QHBoxLayout; run=new QPushButton; run->setObjectName("luksRun"); actions->addWidget(run); refreshButton=new QPushButton("Refresh"); actions->addWidget(refreshButton); cancelAllocation=new QPushButton("Stop allocation"); cancelAllocation->hide(); actions->addWidget(cancelAllocation); connect(cancelAllocation,&QPushButton::clicked,this,[this] {cancelled->store(true); showStatus("Stopping allocation; the incomplete file will be left in place.");}); actions->addStretch(); buttons=new QDialogButtonBox(QDialogButtonBox::Close); actions->addWidget(buttons); layout->addLayout(actions);
        const auto mode=[this,auth] {const auto index=tabs->currentIndex(); run->setText(index==0?"Unlock & mount":index==1?"Create container":"Unmount & lock"); password->clear(); confirmation->clear(); password->setMaxLength(index==1?256:32767); auth->setRowVisible(password,index!=2); auth->setRowVisible(confirmation,index==1); strength->setVisible(index==1); strengthBar->setVisible(index==1); strength->setText("Estimated strength: enter a password/passphrase"); strengthBar->setValue(0);};
        connect(tabs,&QTabWidget::currentChanged,this,[mode](int) {mode();}); mode();
        connect(sourceType,&QComboBox::currentIndexChanged,this,[this,browse](int index) {source->setEnabled(index==0); browse->setEnabled(index==0); devices->setEnabled(index==1);});
        connect(browse,&QPushButton::clicked,this,[this] {QFileDialog picker(this,"Open LUKS container",QDir::homePath()); picker.setOption(QFileDialog::DontUseNativeDialog); picker.setOption(QFileDialog::DontResolveSymlinks); picker.setFileMode(QFileDialog::ExistingFile); if(picker.exec()==QDialog::Accepted) source->setText(picker.selectedFiles().first());});
        connect(choose,&QPushButton::clicked,this,[this] {QFileDialog picker(this,"Create LUKS2 container",destination->text()); picker.setOption(QFileDialog::DontUseNativeDialog); picker.setOption(QFileDialog::DontResolveSymlinks); picker.setOption(QFileDialog::DontConfirmOverwrite); picker.setAcceptMode(QFileDialog::AcceptSave); if(picker.exec()==QDialog::Accepted) destination->setText(picker.selectedFiles().first());});
        connect(run,&QPushButton::clicked,this,[this] {execute();}); connect(refreshButton,&QPushButton::clicked,this,[this] {refresh();}); connect(buttons,&QDialogButtonBox::rejected,this,&QDialog::reject);
        refresh();
    }
    ~Dialog() override {cancelled->store(true); if(allocator && allocator->isRunning()) allocator->wait();}
    void reject() override {if(!busy) QDialog::reject();}
};

inline QWidget* panel(QWidget* parent) {
    auto* widget=new QWidget(parent); widget->setObjectName("luksPanel"); auto* row=new QHBoxLayout(widget); row->setContentsMargins(0,12,0,0);
    row->addWidget(new QLabel("LUKS")); row->addWidget(contextHelp(widget,Help)); row->addStretch();
    const QStringList labels{"Unlock & mount…","Create LUKS2…","Unmount & lock…"};
    for(int i=0;i<labels.size();++i) {auto* button=new QPushButton(labels[i]); row->addWidget(button); QObject::connect(button,&QPushButton::clicked,widget,[widget,i] {Dialog dialog(widget,i); dialog.exec();});}
    return widget;
}
} // namespace Luks
