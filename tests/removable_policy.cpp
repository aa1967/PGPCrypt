#include "../desktop/external_files.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <cstdio>
int main(int argc,char** argv) {
    QCoreApplication app(argc,argv);
    QTemporaryDir fixture;
    if(!fixture.isValid()) return 1;
    const auto file=fixture.filePath("message.txt"); QFile message(file);
    if(!message.open(QIODevice::WriteOnly) || message.write("fixture")!=7) return 2;
    message.close();
    if(!ExternalFilePolicy::allowed(file,false)) return 3;
    // Real filesystem aliases must not bypass path classification, including
    // a not-yet-created output file below the aliased mount.
    if(!QFile::link("/mnt",fixture.filePath("media-alias"))) return 4;
    for(const auto& path:QStringList{"/media/usb/message.txt","/run/media/test/message.txt","/mnt/new-output.txt",fixture.filePath("media-alias/new-output.txt")}) {
        if(ExternalFilePolicy::allowed(path,false) || !ExternalFilePolicy::allowed(path,true)) return 5;
    }
    if(!QFile::link(fixture.path(),fixture.filePath("normal-alias")) || !ExternalFilePolicy::allowed(fixture.filePath("normal-alias/message.txt"),false)) return 6;
    std::puts("Removable-media policy passed: ordinary text, conventional mounts, symlink aliases, new output paths and explicit opt-in.");
}
