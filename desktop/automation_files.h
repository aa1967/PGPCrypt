#pragma once
#include "external_files.h"
#include <QByteArray>
#include <QRandomGenerator>
#include <QStringDecoder>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

namespace AutomationFiles {
constexpr qint64 MaxBytes=4*1024*1024;
inline bool safeName(const QString& name) {
    if(name.trimmed().isEmpty() || name=="." || name==".." || name.toUtf8().size()>240 || name.contains('/') || name.contains('\\')) return false;
    for(auto c:name) if(c.isNull() || c.category()==QChar::Other_Control || c.category()==QChar::Other_Format || c.category()==QChar::Separator_Line || c.category()==QChar::Separator_Paragraph) return false;
    return true;
}
inline QString read(const QString& path,bool media,QString* text) {
    if(!ExternalFilePolicy::allowed(path,media)) return "Removable-media access is disabled.";
    const int fd=::open(QFile::encodeName(path).constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) return "Cannot open a readable regular file; symbolic links are refused.";
    struct stat info{};if(::fstat(fd,&info)!=0 || !S_ISREG(info.st_mode) || info.st_size<0 || info.st_size>MaxBytes || (!media && ExternalFilePolicy::removableDevice(info.st_dev))) {::close(fd);return "Choose an allowed regular message file up to 4 MiB.";}
    QFile file;if(!file.open(fd,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)) {::close(fd);return "Cannot read the message file.";}
    auto bytes=file.read(MaxBytes+1);struct stat after{};const bool stable=::fstat(file.handle(),&after)==0 && after.st_size==info.st_size && after.st_mtim.tv_sec==info.st_mtim.tv_sec && after.st_mtim.tv_nsec==info.st_mtim.tv_nsec && after.st_ctim.tv_sec==info.st_ctim.tv_sec && after.st_ctim.tv_nsec==info.st_ctim.tv_nsec;QStringDecoder decoder(QStringDecoder::Utf8);QString value=decoder(bytes);const bool valid=stable && file.error()==QFileDevice::NoError && bytes.size()<=MaxBytes && !bytes.contains('\0') && !decoder.hasError();bytes.fill('\0');if(!valid) return "Choose UTF-8 text or an armored PGP message (up to 4 MiB).";*text=value;return {};
}
struct Saved {bool committed=false;QString error;};
inline Saved writeNew(const QString& path,QByteArray bytes,bool media) {
    auto fail=[&bytes](const QString& error){bytes.fill('\0');return Saved{false,error};};
    if(bytes.size()>MaxBytes)return fail("Output exceeds the 4 MiB message limit.");
    const QFileInfo target(path);if(!safeName(target.fileName()) || !ExternalFilePolicy::allowed(path,media)) return fail("Choose a permitted output filename and folder.");
    const int directory=::open(QFile::encodeName(target.absolutePath()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(directory<0) return fail("Cannot open the destination folder; choose a writable real folder.");
    struct stat info{};if(::fstat(directory,&info)!=0 || (!media && ExternalFilePolicy::removableDevice(info.st_dev))) {::close(directory);return fail("The destination folder is unavailable or blocked.");}
    QString temporary;int fd=-1;for(int i=0;i<8 && fd<0;++i){temporary=".pgpcrypt-job-"+QString::number(QRandomGenerator::system()->generate64(),16);fd=::openat(directory,QFile::encodeName(temporary).constData(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0 && errno!=EEXIST)break;}
    if(fd<0){::close(directory);return fail("Cannot create a private temporary output.");}
    qint64 offset=0;while(offset<bytes.size()){const auto count=::write(fd,bytes.constData()+offset,bytes.size()-offset);if(count<0 && errno==EINTR)continue;if(count<=0)break;offset+=count;}
    const bool complete=offset==bytes.size() && ::fsync(fd)==0;bytes.fill('\0');::close(fd);
    bool committed=false;if(complete) committed=::linkat(directory,QFile::encodeName(temporary).constData(),directory,QFile::encodeName(target.fileName()).constData(),0)==0;
    const int savedError=errno;::unlinkat(directory,QFile::encodeName(temporary).constData(),0);const bool synced=::fsync(directory)==0;::close(directory);
    if(!complete)return {false,"Output could not be written completely; no destination was published."};
    if(!committed)return {false,savedError==EEXIST?"Destination already exists; it was preserved.":"Cannot publish output; check destination permissions and available space."};
    return {true,synced?QString():QString("Output saved, but folder sync failed. Keep a copy before shutting down.")};
}
inline QString expand(QString pattern,const QString& input,int index,QString workflow) {
    const QFileInfo file(input);for(auto& c:workflow)if(c=='/' || c=='\\' || c.isSpace())c='_';
    // Substitute in one pass so input filenames cannot introduce new tokens.
    QString result;for(int i=0;i<pattern.size();) {if(pattern[i]=='{'){const int end=pattern.indexOf('}',i);if(end<0)return {};const auto token=pattern.mid(i,end-i+1);if(token=="{stem}")result+=file.completeBaseName();else if(token=="{name}")result+=file.fileName();else if(token=="{ext}")result+=file.suffix();else if(token=="{index}")result+=QString::number(index);else if(token=="{workflow}")result+=workflow;else return {};i=end+1;}else result+=pattern[i++];}return result;
}
}
