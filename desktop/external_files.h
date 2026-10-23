#pragma once
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemModel>
#include <QSortFilterProxyModel>
#include <sys/stat.h>
#include <sys/sysmacros.h>

// Application policy for message files, not an OS-wide USB or hostile-host
// boundary. Resolve symlinks and inspect the actual mount's device ancestry.
class ExternalFilePolicy {
    static bool externalLocation(const QString& path) {
        for(const auto& root:QStringList{"/media","/run/media","/mnt"})
            if(path==root || path.startsWith(root+"/")) return true;
        return false;
    }
public:
    static bool removableDevice(dev_t device) {
        const auto link=QString("/sys/dev/block/%1:%2").arg(major(device)).arg(minor(device));
        auto path=QFileInfo(link).canonicalFilePath();
        while(path.startsWith("/sys/devices/")) {
            const auto part=QFileInfo(path).fileName();
            if(part.startsWith("usb") && part.mid(3).toUInt()>0) return true;
            QFile removable(path+"/removable");
            if(removable.open(QIODevice::ReadOnly) && removable.read(16).trimmed()=="1") return true;
            path=QFileInfo(path).absolutePath();
        }
        return false;
    }
    static bool allowed(const QString& filename,bool enabled) {
        if(enabled) return true;
        auto path=QDir::cleanPath(QFileInfo(filename).absoluteFilePath());
        if(externalLocation(path)) return false;
        QFileInfo existing(path);
        while(!existing.exists() && !existing.isSymLink() && existing.absoluteFilePath()!="/") existing.setFile(existing.absolutePath());
        const auto resolved=existing.canonicalFilePath();
        if(resolved.isEmpty() || externalLocation(resolved)) return false;
        struct stat metadata{}; const auto encoded=QFile::encodeName(resolved);
        return ::stat(encoded.constData(),&metadata)==0 && !removableDevice(metadata.st_dev);
    }
};
class ExternalFileFilter final : public QSortFilterProxyModel {
protected:
    bool filterAcceptsRow(int row,const QModelIndex& parent) const override {
        const auto index=sourceModel()->index(row,0,parent);
        const auto path=sourceModel()->data(index,QFileSystemModel::FilePathRole).toString();
        return path.isEmpty() || ExternalFilePolicy::allowed(path,false);
    }
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;
};
