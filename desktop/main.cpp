#include <QApplication>
#include <QCheckBox>
#include <QButtonGroup>
#include <QClipboard>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QComboBox>
#include <QDateTimeEdit>
#include <QDialog>
#include <QDockWidget>
#include <QDialogButtonBox>
#include <QDateTime>
#include <QElapsedTimer>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDir>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QSignalBlocker>
#include <QSlider>
#include <QSpinBox>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSet>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <QGroupBox>
#include <QPalette>
#include <QStyleFactory>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QSettings>
#include <QScrollArea>
#include "external_files.h"
#include "subkey_planner.h"
#include "workflow_editor.h"
#include "automation_files.h"
#include <QScreen>
#include <QRegularExpression>
#include <QTabWidget>
#include <QTabBar>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QStringDecoder>
#include <fcntl.h>
#include <QTimer>
#include <QTimeZone>
#include <QToolBar>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>
#include <functional>
#include <memory>
#include <cstdio>
#include <csignal>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <zxcvbn.h>
#include "ui_helpers.h"

namespace {
constexpr int RestartLocked = 75;
constexpr qsizetype MaxFrame = 10 * 1024 * 1024;
constexpr qsizetype MaxRemoteFrame = 8 * 1024 * 1024;
constexpr qsizetype MaxMessageInput = 4 * 1024 * 1024;
constexpr qsizetype MaxMessageOutput = 4 * 1024 * 1024;
using Reply = std::function<void(bool, const QJsonObject&)>;

bool harden(bool dieWithParent) {
    rlimit limit{0, 0};
    const auto parent = getppid();
    if (dieWithParent && (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 || getppid() != parent)) return false;
    return setrlimit(RLIMIT_CORE, &limit) == 0 && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
}

QPlainTextEdit* editor(const QString& placeholder, bool readonly = false) {
    auto* edit = new QPlainTextEdit;
    edit->setPlaceholderText(placeholder);
    edit->setUndoRedoEnabled(false);
    edit->setReadOnly(readonly);
    edit->setAcceptDrops(false);
    edit->setTabChangesFocus(true);
    return edit;
}

// Typed sorting is shared by every table. Identity membership stays grouped
// first for either direction; dates use UTC seconds rather than display text.
class TableItem final : public QTableWidgetItem {
public:
    explicit TableItem(const QString& text) : QTableWidgetItem(text) {}
    bool operator<(const QTableWidgetItem& other) const override {
        const auto pinned=data(Qt::UserRole+21), otherPinned=other.data(Qt::UserRole+21);
        if(pinned.isValid() && otherPinned.isValid() && pinned.toBool()!=otherPinned.toBool()) {
            const bool descending=tableWidget() && tableWidget()->horizontalHeader()->sortIndicatorOrder()==Qt::DescendingOrder;
            return descending?!pinned.toBool():pinned.toBool();
        }
        const auto first=data(Qt::UserRole+20), second=other.data(Qt::UserRole+20);
        if(first.isValid() && second.isValid()) return first.toLongLong()<second.toLongLong();
        return QString::localeAwareCompare(text().toCaseFolded(),other.text().toCaseFolded())<0;
    }
};

class CheckedKeyTable final : public QTableWidget {
public:
    CheckedKeyTable() : QTableWidget(0,9) {}
    int count() const {return rowCount();}
    QTableWidgetItem* item(int row) const {return QTableWidget::item(row,0);}
    void clear() {setRowCount(0);}
};

void limitNewPassword(QLineEdit* field) {
    field->setMaxLength(256); // 128 Unicode scalars can occupy 256 UTF-16 units.
    QObject::connect(field,&QLineEdit::textChanged,field,[field] {
        const auto scalars=field->text().toUcs4();
        if(scalars.size()>128) field->setText(QString::fromStdU32String(std::u32string(scalars.begin(),scalars.begin()+128)));
    });
}

QWidget* passwordStrength(QLineEdit* field) {
    auto* box=new QWidget; auto* layout=new QVBoxLayout(box); layout->setContentsMargins(0,0,0,0); layout->setSpacing(3);
    auto* label=new QLabel; label->setTextFormat(Qt::PlainText); auto* meter=new QProgressBar; meter->setRange(0,4); meter->setTextVisible(false); meter->setFixedHeight(7);
    layout->addWidget(label); layout->addWidget(meter);
    auto update=[field,label,meter] {
        auto bytes=field->text().toUtf8(); const double entropy=ZxcvbnMatch(bytes.constData(),nullptr,nullptr); bytes.fill('\0');
        const int score=entropy<10?0:entropy<20?1:entropy<26.575?2:entropy<33.22?3:4;
        const QStringList levels{"Very weak","Weak","Fair","Good","Strong"}; meter->setValue(score);
        label->setText("Estimated strength: "+levels[score]+" · Maximum 128 characters; no minimum.");
    };
    QObject::connect(field,&QLineEdit::textChanged,box,update); update(); return box;
}

// This user-requested device preference is separate from encrypted vault
// settings. Never use QSettings for it or serialize a password with a path.
struct RecentVaultStore {
    bool enabled=true, available=true;
    QStringList paths;
    QString directory;

    explicit RecentVaultStore(bool isolatedTest) {
        auto base=isolatedTest?QString():qEnvironmentVariable("XDG_STATE_HOME");
        if(base.isEmpty()) base=QDir::home().filePath(".local/state");
        if(!QDir::isAbsolutePath(base)) {available=enabled=false; return;}
        directory=QDir::cleanPath(base)+"/pgpcrypt";
        load();
    }

    static bool privateFile(const struct stat& metadata) {
        return S_ISREG(metadata.st_mode) && metadata.st_uid==geteuid() && (metadata.st_mode&0777)==0600 && metadata.st_nlink==1;
    }

    static bool validPath(const QString& path) {
        if(path.isEmpty() || !QDir::isAbsolutePath(path) || QDir::cleanPath(path)!=path || path.toUtf8().size()>1024) return false;
        for(const auto ch:path) if(ch.isNull() || ch.category()==QChar::Other_Control) return false;
        return true;
    }

    int openDirectory() const {
        if(directory.isEmpty()) return -1;
        int descriptor=::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if(descriptor<0) return -1;
        const auto components=directory.split('/',Qt::SkipEmptyParts);
        for(const auto& part:components) {
            const auto name=QFile::encodeName(part);
            int next=::openat(descriptor,name.constData(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(next<0 && errno==ENOENT && (::mkdirat(descriptor,name.constData(),0700)==0 || errno==EEXIST)) next=::openat(descriptor,name.constData(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            ::close(descriptor); descriptor=next;
            if(descriptor<0) return -1;
        }
        struct stat metadata{};
        if(::fstat(descriptor,&metadata)!=0 || metadata.st_uid!=geteuid() || (metadata.st_mode&0777)!=0700) {::close(descriptor); return -1;}
        return descriptor;
    }

    void unavailable() {available=false; enabled=false; paths.clear();}

    void load() {
        enabled=true; available=true; paths.clear();
        const int directoryFd=openDirectory(); if(directoryFd<0) {unavailable(); return;}
        const int descriptor=::openat(directoryFd,"recent-vaults.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        const int openError=errno; ::close(directoryFd);
        if(descriptor<0) {if(openError!=ENOENT) unavailable(); return;}
        struct stat metadata{};
        if(::fstat(descriptor,&metadata)!=0 || !privateFile(metadata) || metadata.st_size<0 || metadata.st_size>8192) {::close(descriptor); unavailable(); return;}
        QFile file;
        if(!file.open(descriptor,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)) {::close(descriptor); unavailable(); return;}
        const auto bytes=file.read(8193); QJsonParseError error; const auto document=QJsonDocument::fromJson(bytes,&error);
        if(file.error()!=QFileDevice::NoError || bytes.size()>8192 || error.error!=QJsonParseError::NoError || !document.isObject()) {unavailable(); return;}
        const auto object=document.object();
        if(object.size()!=3 || object.value("schema")!=QJsonValue(1) || !object.value("enabled").isBool() || !object.value("paths").isArray()) {unavailable(); return;}
        const auto entries=object.value("paths").toArray(); if(entries.size()>5 || (!object.value("enabled").toBool() && !entries.isEmpty())) {unavailable(); return;}
        for(const auto& entry:entries) {if(!entry.isString() || !validPath(entry.toString()) || paths.contains(entry.toString())) {unavailable(); return;} paths.append(entry.toString());}
        enabled=object.value("enabled").toBool();
    }

    bool save() {
        if(!available) return false;
        if(!enabled) paths.clear();
        while(paths.size()>5) paths.removeLast();
        QByteArray bytes;
        do {
            QJsonArray entries; for(const auto& path:paths) entries.append(path);
            bytes=QJsonDocument(QJsonObject{{"schema",1},{"enabled",enabled},{"paths",entries}}).toJson(QJsonDocument::Compact);
            if(bytes.size()<=8192) break;
            if(paths.isEmpty()) {unavailable(); return false;}
            paths.removeLast();
        } while(true);
        const int directoryFd=openDirectory(); if(directoryFd<0) {unavailable(); return false;}
        struct stat metadata{};
        if(::fstatat(directoryFd,"recent-vaults.json",&metadata,AT_SYMLINK_NOFOLLOW)==0) {
            if(!privateFile(metadata)) {::close(directoryFd); unavailable(); return false;}
        } else if(errno!=ENOENT) {::close(directoryFd); unavailable(); return false;}
        QByteArray random(16,'\0'); qsizetype generated=0;
        while(generated<random.size()) {const auto count=::getrandom(random.data()+generated,random.size()-generated,0); if(count<0 && errno==EINTR) continue; if(count<=0) {::close(directoryFd); unavailable(); return false;} generated+=count;}
        const auto temporary=QByteArray(".recent-vaults-")+random.toHex()+".tmp";
        const int descriptor=::openat(directoryFd,temporary.constData(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(descriptor<0) {::close(directoryFd); unavailable(); return false;}
        bool ok=::fchmod(descriptor,0600)==0; qsizetype written=0;
        while(ok && written<bytes.size()) {const auto count=::write(descriptor,bytes.constData()+written,bytes.size()-written); if(count<0 && errno==EINTR) continue; if(count<=0) {ok=false; break;} written+=count;}
        if(ok) ok=::fsync(descriptor)==0;
        if(::close(descriptor)!=0) ok=false;
        if(ok) ok=::renameat(directoryFd,temporary.constData(),directoryFd,"recent-vaults.json")==0;
        if(ok) ok=::fsync(directoryFd)==0;
        ::unlinkat(directoryFd,temporary.constData(),0); ::close(directoryFd);
        if(!ok) unavailable();
        return ok;
    }

    void remember(const QString& path) {
        if(!enabled || !available || !validPath(path)) return;
        // Respect a disable setting committed by another session before writing.
        load(); if(!enabled || !available) return;
        paths.removeAll(path); paths.prepend(path); save();
    }
};

class Window final : public QMainWindow {
    Q_OBJECT
public:
    explicit Window(bool selfTest, const QString& screenshot, bool restartProbe = false, bool kdbxProbe = false)
        : testing(selfTest), restartTest(restartProbe), testKdbx(kdbxProbe), screenshotPath(screenshot), recentVaultStore(selfTest) {
        setWindowTitle("PGPCrypt");
        resize(1240, 940);
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.setReadChannel(QProcess::StandardOutput);
        connect(&process, &QProcess::readyReadStandardOutput, this, [this] { receive(); });
        connect(&process, &QProcess::readyReadStandardError, this, [this] { process.readAllStandardError().fill('\0'); });
        connect(&process, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
            if(!ending && pending && process.bytesAvailable()>0) receive();
            if (!ending && (unlocked || pending)) { fail("The crypto worker stopped. This session will close."); endSession(false); }
        });

        root = new QStackedWidget;
        setCentralWidget(root);
        buildLocked();
        buildSession();
        auto* vaultMenu = menuBar()->addMenu("&Vault");
        lockAction = vaultMenu->addAction("&Lock vault", QKeySequence("Ctrl+L"), this, [this] { endSession(true); });
        lockAction->setEnabled(false);
        vaultMenu->addAction("&Quit", QKeySequence::Quit, this, &QWidget::close);
        settingsAction=new QAction(this); settingsAction->setEnabled(false);
        convertAction=new QAction(this); convertAction->setEnabled(false);
        wireClipboard();
        activityDock=new QDockWidget("Session activity",this); activityDock->setObjectName("sessionActivity"); activityDock->setAllowedAreas(Qt::BottomDockWidgetArea);
        auto* activityBox=new QWidget; auto* activityLayout=new QVBoxLayout(activityBox); activityLayout->setContentsMargins(7,4,7,5);
        auto* activityHeading=new QHBoxLayout; auto* activityHint=new QLabel("Activity stays in this window and clears when the vault locks. Public metadata may appear below."); activityHint->setWordWrap(true); activityHeading->addWidget(activityHint,1);
        auto* activityFilter=new QComboBox; activityFilter->addItems({"All activity","Warnings and errors"}); activityHeading->addWidget(activityFilter);
        auto* clearActivity=new QPushButton("Clear"); activityHeading->addWidget(clearActivity); activityLayout->addLayout(activityHeading);
        sessionStats->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont)); sessionStats->setStyleSheet("QLabel { background: #101820; color: #9ed7ff; padding: 8px; border-radius: 4px; }"); sessionStats->setWordWrap(true); activityLayout->addWidget(sessionStats);
        activityWelcome=editor({},true); activityWelcome->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont)); activityWelcome->setLineWrapMode(QPlainTextEdit::NoWrap); activityWelcome->setMaximumHeight(85); activityWelcome->setMinimumHeight(0); activityWelcome->hide(); activityLayout->addWidget(activityWelcome);
        activityLog=new SafeActivityLog; activityLayout->addWidget(activityLog); activityDock->setWidget(activityBox); addDockWidget(Qt::BottomDockWidgetArea,activityDock); activityDock->hide();
        connect(activityFilter,&QComboBox::currentIndexChanged,activityLog,[this](int index) {activityLog->setWarningsOnly(index==1);});
        connect(clearActivity,&QPushButton::clicked,this,[this,activityFilter] {activityFilter->setCurrentIndex(0); resetActivity();});
        activityClearTimer.setSingleShot(false); connect(&activityClearTimer,&QTimer::timeout,this,[this] {if(unlocked) resetActivity();}); vaultMenu->addAction(activityDock->toggleViewAction());

        connect(&rpcServer,&QLocalServer::newConnection,this,[this] { acceptQubes(); });
        auto* help = menuBar()->addMenu("&Help");
        help->addAction("Security boundaries", this, [this] {
            QMessageBox::information(this, "Security boundaries", "Experimental software. Vault contents are encrypted while locked. "
                "Qt text, clipboard managers, swap, and the desktop can retain plaintext. Lock terminates this UI and its crypto worker; "
                "it cannot retract external copies. Public exports and message signatures can reveal identities.");
        });
        statusBar()->showMessage("No system keyring • Experimental version");
        idle.start();
        connect(&idle, &QTimer::timeout, this, [this] {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            if (unlocked && autoLock && (activityClock.elapsed() >= idleTimeoutSeconds * 1000LL || now - lastTick > 15000 || now < lastTick)) endSession(true);
            lastTick = now; updateSessionStats();
        });
        idle.setInterval(1000);
        lastTick = QDateTime::currentMSecsSinceEpoch();
        qApp->installEventFilter(this);
        wireSessionSignals();
        if (testing) QTimer::singleShot(100, this, [this] { testCreate(); });
    }

    ~Window() override {
        ending = true; rpcServer.close(); if(!rpcPath.isEmpty()) QLocalServer::removeServer(rpcPath);
        if (process.state() != QProcess::NotRunning) { process.kill(); process.waitForFinished(5000); }
        incoming.fill('\0');
    }

    void smoke() { QTimer::singleShot(150, qApp, &QCoreApplication::quit); }

public slots:
    void preparingForSleep(bool sleeping) { if (sleeping && unlocked && sessionLock) endSession(true); }
    void sessionLocked() { if (unlocked && sessionLock) endSession(true); }
    void screensaverChanged(bool active) { if (active && unlocked && sessionLock) endSession(true); }

protected:
    bool eventFilter(QObject* object, QEvent* event) override {
        if (event->type() == QEvent::KeyPress || event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseMove)
            activityClock.restart();
        if(object==notepadWindow && event->type()==QEvent::Close && !ending) {
            event->ignore(); notepadWindow->hide(); if(tabs->currentIndex()==1) tabs->setCurrentIndex(0); return true;
        }
        if (focusLock && unlocked && event->type() == QEvent::ApplicationDeactivate) endSession(true);
        return QMainWindow::eventFilter(object, event);
    }
    void closeEvent(QCloseEvent* event) override {
        endSession(false);
        event->accept();
    }

private:
    QProcess process;
    QByteArray incoming;
    Reply pending;
    quint64 sequence = 0;
    quint64 pendingId = 0;
    bool unlocked = false, ending = false, testing = false, restartTest = false, creatingVault = false, testKdbx = false, sessionReadOnly = false;
    QString screenshotPath;
    RecentVaultStore recentVaultStore;
    QListWidget* recentVaultList = nullptr;
    QLabel *recentVaultHeading = nullptr, *recentStorageHint = nullptr;
    QPushButton* forgetRecentButton = nullptr;
    QCheckBox* rememberVaultsCheck = nullptr;
    QTimer idle;
    QTimer strengthTimer;
    QElapsedTimer activityClock;
    int idleTimeoutSeconds = 300, clipboardSeconds = 0;
    bool autoLock = false, focusLock = false, sessionLock = false, qubesEnabled = false;
    QJsonObject preferences, workerSecurity;
    QTimer activityClearTimer;
    QElapsedTimer sessionClock;
    quint64 sessionOperations=0, failedOpens=0;
    QLabel *sessionStats=nullptr, *memoryStatus=nullptr;
    std::function<void()> syncSettingsControls;
    QTimer clipboardTimer, selectionTimer;
    QAction *settingsAction = nullptr, *convertAction = nullptr;
    qint64 lastTick = 0;
    QStackedWidget *root = nullptr;
    QWidget *sessionPage = nullptr, *lockedPage = nullptr, *homePage = nullptr, *workspaceBody = nullptr;
    QLineEdit *path = nullptr, *password = nullptr, *confirmation = nullptr, *search = nullptr;
    QLabel *vaultTitle = nullptr, *confirmationLabel = nullptr, *strengthLabel = nullptr, *passwordHint = nullptr, *matchStatus = nullptr;
    QProgressBar* strengthMeter = nullptr;
    QComboBox* formatChoice = nullptr;
    QLabel* formatLabel = nullptr;
    QString currentFormat = "age", activeVaultPath;
    QLabel* sessionWarning = nullptr;
    QPushButton* unlockButton = nullptr;
    QLabel *lockedStatus = nullptr, *details = nullptr, *selectionSummary = nullptr;
    QTableWidget* keys = nullptr;
    QTabWidget* tabs = nullptr;
    QPlainTextEdit *importText = nullptr, *input = nullptr, *output = nullptr;
    QAction* lockAction = nullptr;
    QString signer, defaultSigner;
    CheckedKeyTable* recipientChoices = nullptr;
    QComboBox* signingChoice = nullptr;
    QLabel* defaultKeyLabel = nullptr;
    QString testFingerprint;
    QTabBar* profileTabs = nullptr;
    QJsonArray cachedKeys, profiles;
    QString activeProfile, currentDocumentId, currentDocumentTitle;
    QComboBox* profileSelector = nullptr;
    QLineEdit* profileName = nullptr;
    CheckedKeyTable* profileMembers = nullptr;
    QLineEdit *profileUsername=nullptr, *profileEmail=nullptr, *profileUrl=nullptr, *identitySearch=nullptr, *documentSearch=nullptr;
    QPlainTextEdit* profileNotes=nullptr;
    QComboBox *identityStatus=nullptr, *keyStatus=nullptr;
    QString currentDocumentProfile;
    QTableWidget *documents = nullptr, *recentDocuments = nullptr;
    QLabel *documentContext = nullptr, *verificationIdentity = nullptr;
    QPushButton *pasteInput = nullptr, *copyOutput = nullptr, *profileSaveButton = nullptr, *profileDeleteButton = nullptr;
    QList<QPushButton*> navigationButtons;
    QList<QWidget*> vaultMutationControls;
    QLabel* readOnlySettingsNote = nullptr;
    QCheckBox* protectionMasterCheck = nullptr;
    QList<QWidget*> protectionOptionControls;
    QList<QCheckBox*> protectionOptionChecks;
    QJsonObject protectionOptions;
    bool protectionMaster = false, protectionLoaded = false;
    bool outputIsEncrypted = false, notepadPopout = false;
    QWidget *notepadPage=nullptr, *notepadHost=nullptr, *notepadPlaceholder=nullptr;
    QVBoxLayout* notepadHostLayout=nullptr;
    QDialog* notepadWindow=nullptr;
    QTabBar* notepadProfileTabs=nullptr;
    QPointer<QDialog> verificationPopup;
    QDockWidget* activityDock=nullptr;
    SafeActivityLog* activityLog=nullptr;
    QTableWidget* identityOverview=nullptr;
    QJsonObject profileDocumentCounts;
    QString pendingOperation, editedIdentityId;
    QStringList pendingActivity;
    bool workflowRunning=false, expectedTestError=false;
    QComboBox* workflowChoice=nullptr;
    WorkflowEditor* workflowEditor=nullptr;
    QComboBox* workflowSource=nullptr;
    QList<QPointer<QDialog>> jobWindows;
    qint64 retainedJobBytes=0;
    struct BatchJob {QString inputPath,outputPath;};
    struct BatchRun {QJsonObject preset,context;QList<BatchJob> jobs;int index=0,success=0,failed=0;bool continueOnError=true,stopRequested=false;std::function<void()> after;};
    std::shared_ptr<BatchRun> activeBatch;
    QPlainTextEdit* activityWelcome=nullptr;
    QJsonObject outputProof;
    QByteArray outputProofDigest;
    QList<QPushButton*> outputActions;
    struct WorkflowRun {
        QString name, text, originalOutput;
        QJsonObject context, proof, lastResult;
        QJsonArray steps;
        int index=0;
        bool fromOutput=false, originalEncrypted=false;
        std::function<void()> after;
        std::function<void(bool,const QJsonObject&)> completion;
        bool batch=false;
    };
    std::shared_ptr<WorkflowRun> activeWorkflow;

    bool identityDirty=false, loadingIdentity=false;
    QSet<QString> identityBaselineMembers;

    QLocalServer rpcServer;
    bool rpcBusy=false;
    QElapsedTimer rpcRate;
    int rpcConnections=0;
    QString rpcPath;

    void fail(const QString& message) {
        statusBar()->showMessage(message);
        lockedStatus->setText(message);
        if (testing && !expectedTestError) { std::fprintf(stderr,"Qt desktop self-test FAILED: %s\n",message.toUtf8().constData()); ending = true; process.kill(); process.waitForFinished(5000); qApp->exit(1); }
    }

    void request(const QString& operation, QJsonObject fields, Reply callback) {
        if (pending || ending) { fail("Another operation is in progress"); return; }
        if(sessionReadOnly && QStringList{"generate","import","add_subkey","add_subkeys","protect_private_key","profile_save","profile_delete","document_save","document_properties","document_delete","settings_set","convert_copy","emergency_set","emergency_disable","dummy_set","dummy_disable","protection_enable","protection_disable","protection_option_enable","protection_option_disable","expiry_set","expiry_disable","notes_set"}.contains(operation)) {fail("Action unavailable in this session."); return;}
        if (process.state() == QProcess::NotRunning) {
            process.setProgram(QCoreApplication::applicationDirPath() + "/pgpcrypt-worker");
            process.start();
            if (!process.waitForStarted(5000)) { fail("Cannot start crypto worker"); return; }
        }
        fields.insert("op", operation);
        fields.insert("id", static_cast<qint64>(++sequence));
        auto bytes = QJsonDocument(fields).toJson(QJsonDocument::Compact);
        bytes.append('\n');
        if (bytes.size() > MaxFrame) { bytes.fill('\0'); fail("Input exceeds the application limit"); return; }
        pendingActivity=activityContext(operation,fields);
        pendingOperation=operation;
        pendingId = sequence;
        pending = std::move(callback);
        syncBusyUi();
        lockedPage->setEnabled(false);
        unlockButton->setEnabled(false);
        statusBar()->showMessage("Working… You can lock or close this session to cancel.");
        process.write(bytes);
        bytes.fill('\0'); // Best effort; QProcess/Qt may retain their own copies.
    }

    void receive() {
        incoming += process.readAllStandardOutput();
        if (incoming.size() > MaxFrame) { fail("Invalid worker response"); endSession(false); return; }
        const auto newline = incoming.indexOf('\n');
        if (newline < 0) return;
        if (!pending || newline != incoming.size() - 1) { fail("Unexpected worker response"); endSession(false); return; }
        QJsonParseError error;
        const auto response = QJsonDocument::fromJson(incoming, &error).object();
        incoming.fill('\0'); incoming.clear();
        if (error.error != QJsonParseError::NoError || response.value("id").toInteger() != static_cast<qint64>(pendingId)) {
            fail("Invalid worker response"); endSession(false); return;
        }
        auto callback = std::move(pending); pending = {};
        syncBusyUi(); lockedPage->setEnabled(true);
        const bool ok = response.value("ok").toBool();
        const auto code=response.value("code").toString();
        if(!ok && code=="vault_reopen_required") {
            const QString message="The vault was saved, but a storage update failed. Reopen it and check protection in Vault settings. Keep a backup before shutting down.";
            if(testing) {fail(message); return;}
            endSession(true,message); return;
        }
        const auto completedOperation=pendingOperation; pendingOperation.clear();
        auto activityDetails=std::move(pendingActivity); pendingActivity.clear();
        const auto replyData=response.value("data").toObject();
        if(replyData.contains("key")) activityDetails.append(activityKey(replyData.value("key").toObject()));
        for(const auto& value:replyData.value("decryption_keys").toArray()) activityDetails.append(activityKey(keyRecord(value.toString())));
        if(replyData.contains("title")) activityDetails.append("Document: "+SafeActivityLog::field(replyData.value("title").toString()));
        for(const auto& fp:replyData.value("signing_keys").toArray()) activityDetails.append(activityKey(keyRecord(fp.toString())));
        if(replyData.contains("added")) activityDetails.append("Subkeys added: "+QString::number(replyData.value("added").toInt()));
        if(!ok) activityDetails.append(activityReason(response.value("diagnostic").toString(),code));
        if(completedOperation=="open" && !ok) ++failedOpens;
        if(ok && (completedOperation=="open" || completedOperation=="create")) {workerSecurity=response.value("data").toObject().value("security").toObject(); sessionClock.start(); sessionOperations=0;}
        const QHash<QString,ActivityEvent> events{{"generate",ActivityEvent::KeyCreated},{"import",ActivityEvent::KeyImported},{"add_subkey",ActivityEvent::SubkeyAdded},{"add_subkeys",ActivityEvent::SubkeyAdded},{"protect_private_key",ActivityEvent::KeyUpdated},{"settings_set",ActivityEvent::PreferencesSaved},{"profile_save",ActivityEvent::IdentityUpdated},{"profile_delete",ActivityEvent::IdentityUpdated},{"revocation_export",ActivityEvent::OperationComplete},{"document_save",ActivityEvent::DocumentSaved},{"document_get",ActivityEvent::TextLoaded},{"document_properties",ActivityEvent::DocumentChanged},{"document_delete",ActivityEvent::DocumentChanged},{"encrypt",ActivityEvent::EncryptionComplete},{"decrypt",ActivityEvent::DecryptionComplete},{"sign",ActivityEvent::SigningComplete},{"public_export",ActivityEvent::OperationComplete},{"private_export",ActivityEvent::OperationComplete},{"protected_private_export",ActivityEvent::OperationComplete}};
        // No activity entries for password roles, protection setup or unlocks.
        if(activityLog && unlocked && events.contains(completedOperation) && code!="password_required" && code!="vault_auth_required") {activityLog->record(ok?events.value(completedOperation):ActivityEvent::OperationFailed,activityDetails); if(ok) ++sessionOperations;}
        if(ok && completedOperation=="verify") ++sessionOperations;
        updateSessionStats();
        if (!ok && code!="password_required" && code!="vault_auth_required" && code!="verification_failed") fail(response.value("error").toString("Operation failed"));
        else statusBar()->showMessage("Ready");
        auto data=response.value("data").toObject(); if(!ok) {data.insert("_error_code",code);data.insert("_required_key",response.value("required_key"));}
        if (callback) callback(ok,data);
        updateVaultSubmit();
    }

    void endSession(bool restart, const QString& notice = {}) {
        if (ending) return;
        ending = true;
        if(verificationPopup) {verificationPopup->close(); verificationPopup.clear();}
        if(notepadWindow) notepadWindow->hide();
        workflowRunning=false; activeWorkflow.reset(); activeBatch.reset(); for(auto& window:jobWindows) if(window) {for(auto* text:window->findChildren<QPlainTextEdit*>()) text->clear();window->close();} jobWindows.clear(); retainedJobBytes=0; outputProof={}; outputProofDigest.clear(); if(activityWelcome) activityWelcome->clear(); if(sessionStats) sessionStats->clear();
        if(activityLog) {activityLog->clear();} if(activityDock) {activityDock->hide();}
        idle.stop(); rpcServer.close(); if(!rpcPath.isEmpty()) {QLocalServer::removeServer(rpcPath); rpcPath.clear();}
        activityClearTimer.stop(); clipboardTimer.stop(); selectionTimer.stop();
        clearSessionClipboard(); clearSessionClipboard(QClipboard::Selection);
        if(testing && !qApp->clipboard()->text().isEmpty()) {std::fputs("Clipboard survived lock\n",stderr); qApp->exit(1); return;}
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            if (!process.waitForFinished(5000)) { ending = false; idle.start(); fail("Worker could not be stopped; vault lock is not confirmed"); return; }
        }
        unlocked = false;
        if(!testing && !notice.isEmpty()) {
            root->setCurrentWidget(homePage);
            input->clear(); output->clear(); keys->setRowCount(0);
            recipientChoices->clear(); signingChoice->clear();
            settingsAction->setEnabled(false); convertAction->setEnabled(false);
            QMessageBox::warning(this,"Reopen vault",notice);
        }
        if (testing) {
            if((activityLog && !activityLog->toPlainText().isEmpty()) || (notepadWindow && notepadWindow->isVisible()) || (verificationPopup && verificationPopup->isVisible())) {std::fputs("Qt desktop self-test FAILED: sensitive child UI survived lock\n",stderr); qApp->exit(1); return;}
            std::fputs("Qt desktop self-test passed: create, generate, encrypt, decrypt, sign, verify, notes, lock; worker terminated\n", stdout);
            qApp->exit(restartTest ? RestartLocked : 0);
        } else qApp->exit(restart ? RestartLocked : 0);
    }

    void wireSessionSignals() {
        auto system = QDBusConnection::systemBus();
        system.connect("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "PrepareForSleep", this, SLOT(preparingForSleep(bool)));
        QDBusInterface manager("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", system);
        if (manager.isValid()) {
            QDBusReply<QDBusObjectPath> session = manager.call("GetSessionByPID", static_cast<uint>(QCoreApplication::applicationPid()));
            if (session.isValid()) system.connect("org.freedesktop.login1", session.value().path(), "org.freedesktop.login1.Session", "Lock", this, SLOT(sessionLocked()));
        }
        QDBusConnection::sessionBus().connect("org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", this, SLOT(screensaverChanged(bool)));
    }

    void buildLocked() {
        homePage = new QWidget;
        auto* welcome = new QVBoxLayout(homePage);
        welcome->setContentsMargins(100,60,100,60); welcome->addStretch();
        auto* title = new QLabel("PGPCrypt"); title->setStyleSheet("font-size: 36px; font-weight: 600;");
        welcome->addWidget(title);
        auto* subtitle = new QLabel("Keep your OpenPGP keys in an encrypted vault.");
        subtitle->setWordWrap(true); welcome->addWidget(subtitle); welcome->addSpacing(28);
        auto* createVault = new QPushButton("Create vault");
        auto* openVault = new QPushButton("Open vault");
        auto* quit = new QPushButton("Quit");
        for(auto* button : {createVault,openVault,quit}) { button->setMinimumHeight(52); welcome->addWidget(button); }
        createVault->setDefault(true);
        connect(createVault,&QPushButton::clicked,this,[this] { showVaultForm(true); });
        connect(openVault,&QPushButton::clicked,this,[this] { browseOpenVault(); });
        connect(quit,&QPushButton::clicked,this,&QWidget::close);
        welcome->addSpacing(20);
        recentVaultHeading=new QLabel("Recent vaults"); recentVaultHeading->setStyleSheet("font-weight: 600;"); welcome->addWidget(recentVaultHeading);
        recentVaultList=new QListWidget; recentVaultList->setMaximumHeight(180); recentVaultList->setAlternatingRowColors(true); recentVaultList->setSpacing(3); welcome->addWidget(recentVaultList);
        connect(recentVaultList,&QListWidget::itemClicked,this,[this](QListWidgetItem* item) {openRecentVault(item);});
        forgetRecentButton=new QPushButton("Forget recent vaults"); welcome->addWidget(forgetRecentButton);
        connect(forgetRecentButton,&QPushButton::clicked,this,[this] {recentVaultStore.paths.clear(); const bool saved=recentVaultStore.save(); updateRecentVaultUi(); statusBar()->showMessage(saved?"Recent vault paths cleared.":"Stored recent paths could not be cleared. History is disabled for this session.");});
        updateRecentVaultUi();
        welcome->addWidget(new QLabel("Key management • age and KeePass vaults"));
        welcome->addStretch();
        root->addWidget(homePage);

        lockedPage = new QWidget;
        auto* outer = new QVBoxLayout(lockedPage);
        outer->setContentsMargins(100, 60, 100, 60);
        auto* back = new QPushButton("← Back");
        auto* backRow = new QHBoxLayout; backRow->addWidget(back); backRow->addStretch(); outer->addLayout(backRow);
        connect(back,&QPushButton::clicked,this,[this] { clearVaultCredentials(); path->clear(); lockedStatus->clear(); root->setCurrentWidget(homePage); });
        vaultTitle = new QLabel; vaultTitle->setStyleSheet("font-size: 28px; font-weight: 600;"); outer->addWidget(vaultTitle);
        outer->addSpacing(28);
        auto* form = new QFormLayout;
        auto* pathRow = new QHBoxLayout;
        path = new QLineEdit;
        auto* browse = new QPushButton("Browse…"); pathRow->addWidget(path); pathRow->addWidget(browse);
        connect(browse,&QPushButton::clicked,this,[this] { browseVaultPath(creatingVault); });
        form->addRow("Vault file",pathRow);
        formatChoice = new QComboBox;
        formatChoice->addItem("age v1", "age"); formatChoice->addItem("KeePass KDBX 4.1 (alpha support)", "kdbx");
        formatLabel = new QLabel("Vault format"); form->addRow(formatLabel,formatChoice);
        connect(formatChoice,&QComboBox::currentIndexChanged,this,[this] {
            auto value=path->text();
            if(value.endsWith(".pgpcrypt.age")) value.chop(13);
            else if(value.endsWith(".kdbx")) value.chop(5);
            else return;
            path->setText(value+(formatChoice->currentData().toString()=="kdbx"?".kdbx":".pgpcrypt.age"));
        });
        password = new QLineEdit; password->setEchoMode(QLineEdit::Password);
        password->setMaxLength(256);
        password->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
        form->addRow("Password/passphrase",password);
        confirmation = new QLineEdit; confirmation->setEchoMode(QLineEdit::Password);
        confirmation->setMaxLength(256); confirmation->setInputMethodHints(password->inputMethodHints());
        confirmationLabel = new QLabel("Confirm password/passphrase"); form->addRow(confirmationLabel,confirmation);
        outer->addLayout(form);
        strengthLabel = new QLabel; strengthLabel->setTextFormat(Qt::PlainText); outer->addWidget(strengthLabel);
        strengthMeter = new QProgressBar; strengthMeter->setRange(0,4); strengthMeter->setTextVisible(false); strengthMeter->setFixedHeight(10); outer->addWidget(strengthMeter);
        passwordHint = new QLabel("No minimum length. Use a strong random password or passphrase; an empty password offers no guessing resistance. Maximum 128 characters. There is no password reset.");
        passwordHint->setWordWrap(true); outer->addWidget(passwordHint);
        matchStatus = new QLabel; matchStatus->setTextFormat(Qt::PlainText); outer->addWidget(matchStatus);
        strengthTimer.setSingleShot(true); strengthTimer.setInterval(180);
        connect(&strengthTimer,&QTimer::timeout,this,[this] { updatePasswordStrength(); });
        connect(password,&QLineEdit::textChanged,this,[this] {
            if(creatingVault && password->text().toUcs4().size()>128) {const auto chars=password->text().toUcs4(); password->setText(QString::fromStdU32String(std::u32string(chars.begin(),chars.begin()+128))); return;}
            updateVaultSubmit();
            if(creatingVault) { strengthMeter->setValue(0); strengthLabel->setText(password->text().isEmpty()?"Estimated strength: enter a password/passphrase":"Estimating strength…"); strengthTimer.start(); }
        });
        connect(confirmation,&QLineEdit::textChanged,this,[this] { updateVaultSubmit(); });
        connect(path,&QLineEdit::textChanged,this,[this] { updateVaultSubmit(); });
        unlockButton = new QPushButton;
        outer->addWidget(unlockButton);
        connect(password,&QLineEdit::returnPressed,this,[this] { if(creatingVault) confirmation->setFocus(); else unlockButton->click(); });
        connect(confirmation,&QLineEdit::returnPressed,unlockButton,&QPushButton::click);
        connect(unlockButton,&QPushButton::clicked,this,[this] {
            if(creatingVault && password->text()!=confirmation->text()) { fail("Passwords/passphrases must match"); return; }
            const auto filename = absoluteVaultPath(path->text());
            if(filename.isEmpty()) { fail("Choose a vault file"); return; }
            path->setText(filename); lockedStatus->clear();
            QJsonObject fields{{"path",filename},{"password",password->text()}};
            if(creatingVault) fields.insert("format",formatChoice->currentData().toString());
            const auto op = creatingVault ? "create" : "open";
            clearVaultCredentials();
            request(op,fields,[this](bool ok,const QJsonObject& data) {
                if (!ok) return;
                unlocked = true; if(activityLog) {activityLog->clear(); activityLog->record(ActivityEvent::SessionReady);} if(activityDock) activityDock->show(); sessionReadOnly=data.value("read_only").toBool(); lockAction->setEnabled(true); root->setCurrentWidget(sessionPage);
                currentFormat=data.value("format").toString("age"); activeVaultPath=path->text();
                if(activityLog) activityLog->record(ActivityEvent::OperationComplete,{"Vault: "+SafeActivityLog::field(QFileInfo(activeVaultPath).fileName())});
                recentVaultStore.remember(activeVaultPath); updateRecentVaultUi();
                settingsAction->setEnabled(!sessionReadOnly); convertAction->setEnabled(!sessionReadOnly);
                idleTimeoutSeconds=data.value("idle_timeout_seconds").toInt(300); applyPreferences(data.value("preferences").toObject()); applyReadOnlyUi();
                path->clear(); lockedStatus->clear();
                activityClock.restart();
                const auto protectionWarning=data.value("protection_warning").toString();
                refreshKeys([this,protectionWarning] {if(testing) testGenerate(); else if(!protectionWarning.isEmpty()) QMessageBox::warning(this,"Vault configuration",protectionWarning); else statusBar()->showMessage("Ready");});
            });
        });
        lockedStatus = new QLabel; lockedStatus->setTextFormat(Qt::PlainText); lockedStatus->setWordWrap(true); outer->addWidget(lockedStatus);
        outer->addStretch();
        auto* warning = new QLabel("Alpha version • Keep backups. Vault filename and size remain visible while locked.");
        warning->setWordWrap(true); outer->addWidget(warning);
        root->addWidget(lockedPage);
    }

    void updateRecentVaultUi() {
        if(recentVaultList) {
            recentVaultList->clear();
            if(recentVaultStore.available && recentVaultStore.enabled) for(const auto& filename:recentVaultStore.paths) {auto* item=new QListWidgetItem(QFileInfo(filename).fileName()+"\n"+filename,recentVaultList); item->setData(Qt::UserRole,filename); item->setToolTip(filename);}
            const bool has=recentVaultList->count()>0; recentVaultList->setVisible(has); recentVaultHeading->setVisible(has); forgetRecentButton->setVisible(has);
        }
        if(rememberVaultsCheck) {QSignalBlocker block(rememberVaultsCheck); rememberVaultsCheck->setChecked(recentVaultStore.enabled && recentVaultStore.available); rememberVaultsCheck->setEnabled(recentVaultStore.available);}
        if(recentStorageHint) recentStorageHint->setText(recentVaultStore.available?"Stores vault paths outside encryption; never passwords. Disable to clear.":"Recent-vault history is unavailable. No new paths will be remembered; an older history file could not be read, cleared or updated.");
    }

    void setRememberVaults(bool enabled) {
        recentVaultStore.enabled=enabled;
        if(!enabled) recentVaultStore.paths.clear();
        if(enabled && unlocked && RecentVaultStore::validPath(activeVaultPath)) {recentVaultStore.paths.removeAll(activeVaultPath); recentVaultStore.paths.prepend(activeVaultPath);}
        const bool saved=recentVaultStore.save(); updateRecentVaultUi();
        if(activityLog && unlocked) activityLog->record(saved?ActivityEvent::PreferencesSaved:ActivityEvent::OperationFailed,{QString("Remember recent vaults: ")+(enabled?"on":"off"),saved?QString("Saved on this device"):QString("Could not update the local history file")});
        statusBar()->showMessage(saved?(enabled?"Recent vaults will be remembered on this device.":"Recent vault paths cleared; remembering is disabled."):"Could not save the recent-vault setting or clear stored paths. History is disabled for this session.");
    }

    void openRecentVault(QListWidgetItem* item) {
        if(!item || unlocked || pending) return;
        const auto filename=item->data(Qt::UserRole).toString(); if(RecentVaultStore::validPath(filename)) showVaultForm(false,filename);
    }

    static QString absoluteVaultPath(const QString& value) {
        if(value.isEmpty()) return {};
        if(value=="~") return QDir::homePath();
        if(value.startsWith("~/")) return QDir::cleanPath(QDir::home().filePath(value.mid(2)));
        if(QDir::isRelativePath(value)) return QDir::cleanPath(QDir::home().absoluteFilePath(value));
        return QDir::cleanPath(value);
    }

    void clearVaultCredentials() {
        password->clear(); confirmation->clear(); strengthTimer.stop();
        strengthMeter->setValue(0); strengthLabel->setText("Estimated strength: enter a password/passphrase"); matchStatus->clear();
    }

    void updateVaultSubmit() {
        if(!unlockButton) return;
        const bool matches=password->text()==confirmation->text();
        unlockButton->setEnabled(!pending && !ending && !path->text().isEmpty()
            && (!creatingVault || matches));
        if(matchStatus) matchStatus->setText(creatingVault && !confirmation->text().isEmpty() && !matches?"Passwords/passphrases do not match.":QString());
    }

    void updatePasswordStrength() {
        if(!creatingVault) return;
        auto bytes=password->text().toUtf8();
        // zxcvbn recognizes common passwords, repetitions and keyboard patterns.
        // No password is sent to a worker, network service or external process.
        const double entropy=ZxcvbnMatch(bytes.constData(),nullptr,nullptr);
        bytes.fill('\0');
        const int score=entropy<10?0:entropy<20?1:entropy<26.575?2:entropy<33.22?3:4;
        const QStringList levels{"Very weak","Weak","Fair","Good","Strong"};
        strengthMeter->setValue(score);
        strengthLabel->setText("Estimated strength: "+levels[score]+" (an estimate, not a guarantee)");
        const QStringList colors{"#b91c1c","#c2410c","#a16207","#15803d","#047857"};
        strengthMeter->setStyleSheet("QProgressBar::chunk { background: "+colors[score]+"; }");
    }

    void showVaultForm(bool createNew, const QString& selected = {}) {
        creatingVault=createNew; clearVaultCredentials(); lockedStatus->clear();
        formatChoice->setVisible(createNew); formatLabel->setVisible(createNew);
        password->setMaxLength(createNew?256:32767);
        vaultTitle->setText(createNew?"Create vault":"Open vault");
        confirmation->setVisible(createNew); confirmationLabel->setVisible(createNew);
        strengthLabel->setVisible(createNew); strengthMeter->setVisible(createNew); passwordHint->setVisible(createNew); matchStatus->setVisible(createNew);
        unlockButton->setText(createNew?"Create vault":"Unlock vault");
        path->setText(selected.isEmpty() && createNew?QDir::home().filePath(formatChoice->currentData().toString()=="kdbx"?"vault.kdbx":"vault.pgpcrypt.age"):selected);
        root->setCurrentWidget(lockedPage); password->setFocus(); updateVaultSubmit();
    }

    void browseOpenVault() {
        const auto filename=chooseVaultPath(false, QDir::homePath());
        if(!filename.isEmpty()) showVaultForm(false,filename);
    }

    QString chooseVaultPath(bool save, const QString& initial, const QString& targetFormat = {}) {
        QFileDialog dialog(this,save?"Choose where to save your vault":"Open vault",initial);
        // The Qt browser keeps selection inside this process. QSettings writes
        // are disabled in main so Qt cannot persist its directory/history.
        dialog.setOption(QFileDialog::DontUseNativeDialog);
        dialog.setOption(QFileDialog::DontResolveSymlinks);
        dialog.setOption(QFileDialog::DontConfirmOverwrite);
        dialog.setAcceptMode(save?QFileDialog::AcceptSave:QFileDialog::AcceptOpen);
        dialog.setFileMode(save?QFileDialog::AnyFile:QFileDialog::ExistingFile);
        dialog.setNameFilters({"Encrypted vaults (*.pgpcrypt.age *.age *.kdbx)","All files (*)"});
        if(save) dialog.setDefaultSuffix((targetFormat.isEmpty()?formatChoice->currentData().toString():targetFormat)=="kdbx"?"kdbx":"pgpcrypt.age");
        if(dialog.exec()!=QDialog::Accepted || dialog.selectedFiles().isEmpty()) return {};
        return absoluteVaultPath(dialog.selectedFiles().first());
    }

    void browseVaultPath(bool save) {
        const auto filename=chooseVaultPath(save,absoluteVaultPath(path->text()));
        if(!filename.isEmpty()) {
            path->setText(filename);
            if(save && QFileInfo::exists(filename)) fail("That file already exists. Choose another name; existing vaults are never overwritten.");
        }
    }

    void convertVault() {
        if(!unlocked || pending) return;
        QDialog dialog(this); dialog.setWindowTitle("Save converted vault copy");
        auto* layout=new QVBoxLayout(&dialog); auto* form=new QFormLayout;
        auto* info=new QLabel("Both destination formats—age v1 and KeePass KDBX 4.1—copy your keys, identities, saved documents and vault preferences. The original stays open and unchanged. Unrelated KeePass entries remain only in the original KDBX.\n\nNeither format copies PGPCrypt's adjacent advanced-protection records (dummy password, emergency destruction or inactivity deletion). These options start off in every converted copy and must be configured separately. KeePassXC does not implement them.");
        info->setWordWrap(true); layout->addWidget(info);
        auto* format=new QComboBox; format->addItem("age v1","age"); format->addItem("KeePass KDBX 4.1 (alpha support)","kdbx"); format->setCurrentIndex(currentFormat=="age"?1:0); form->addRow("Destination format",format);
        auto* filename=new QLineEdit; auto* row=new QHBoxLayout; auto* browse=new QPushButton("Browse…"); row->addWidget(filename); row->addWidget(browse); form->addRow("New vault file",row);
        auto* pass=new QLineEdit; pass->setEchoMode(QLineEdit::Password); pass->setMaxLength(256); pass->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText);
        auto* confirm=new QLineEdit; confirm->setEchoMode(QLineEdit::Password); confirm->setMaxLength(256); confirm->setInputMethodHints(pass->inputMethodHints());
        form->addRow("New password/passphrase",pass); form->addRow("Confirm password/passphrase",confirm); layout->addLayout(form);
        limitNewPassword(pass); limitNewPassword(confirm); layout->addWidget(passwordStrength(pass));
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); layout->addWidget(buttons);
        auto update=[=] {buttons->button(QDialogButtonBox::Save)->setEnabled(!filename->text().isEmpty() && pass->text()==confirm->text());};
        connect(pass,&QLineEdit::textChanged,&dialog,update); connect(confirm,&QLineEdit::textChanged,&dialog,update); connect(filename,&QLineEdit::textChanged,&dialog,update);
        connect(browse,&QPushButton::clicked,&dialog,[&] { const auto value=chooseVaultPath(true,QDir::homePath(),format->currentData().toString()); if(!value.isEmpty()) filename->setText(value); });
        connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); update();
        if(dialog.exec()!=QDialog::Accepted) { pass->clear(); confirm->clear(); return; }
        QJsonObject fields{{"path",absoluteVaultPath(filename->text())},{"password",pass->text()},{"format",format->currentData().toString()}};
        pass->clear(); confirm->clear();
        request("convert_copy",fields,[this](bool ok,const QJsonObject&) { if(ok) statusBar()->showMessage("Converted copy saved. Original vault stays open and unchanged."); });
    }

    void buildSession() {
        sessionPage = new QWidget;
        auto* layout = new QVBoxLayout(sessionPage);
        auto* heading = new QHBoxLayout;
        auto* title = new QLabel("PGPCrypt"); title->setStyleSheet("font-size: 24px; font-weight: 600;");
        heading->addWidget(title); sessionStats=new QLabel; sessionStats->setTextFormat(Qt::PlainText); heading->addStretch();
        auto* lock = new QPushButton("Lock vault  Ctrl+L"); heading->addWidget(lock);
        connect(lock,&QPushButton::clicked,this,[this] { endSession(true); });
        layout->addLayout(heading);
        workspaceBody = new QWidget; auto* body=new QHBoxLayout(workspaceBody); body->setContentsMargins(0,0,0,0);
        auto* navigation=new QWidget; auto* navLayout=new QVBoxLayout(navigation); navLayout->setContentsMargins(0,0,8,0); navLayout->setSpacing(10);
        navigation->setMinimumWidth(140); navigation->setMaximumWidth(170);
        auto* buttonGroup=new QButtonGroup(this); buttonGroup->setExclusive(true);
        for(const auto& name:QStringList{"Keys","Notepad","Identities","Saved notes","Automation","Vault settings"}) {
            auto* button=new QPushButton(name); button->setCheckable(true); button->setMinimumHeight(58); button->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
            button->setStyleSheet("QPushButton { font-size: 15px; font-weight: 600; border-radius: 7px; padding: 12px; } QPushButton:checked { background: palette(highlight); color: palette(highlighted-text); }");
            buttonGroup->addButton(button,navigationButtons.size()); navigationButtons.append(button); navLayout->addWidget(button,1);
        }
        body->addWidget(navigation);
        auto* content=new QWidget; auto* contentLayout=new QVBoxLayout(content); contentLayout->setContentsMargins(0,0,0,0);
        profileTabs=new QTabBar; profileTabs->setExpanding(false); profileTabs->setUsesScrollButtons(true); profileTabs->setDrawBase(true); profileTabs->addTab("All"); profileTabs->setTabData(0,QString()); profileTabs->addTab("+");
        contentLayout->addWidget(profileTabs);
        tabs = new QTabWidget; tabs->tabBar()->hide();
        buildKeys(); buildText(); buildIdentities(); buildSavedNotes(); buildAutomation(); buildSettingsPage();
        contentLayout->addWidget(tabs,1); body->addWidget(content,1);
        connect(buttonGroup,&QButtonGroup::idClicked,tabs,&QTabWidget::setCurrentIndex);
        connect(tabs,&QTabWidget::currentChanged,this,[this](int index) {
            if(index>=0 && index<navigationButtons.size()) navigationButtons[index]->setChecked(true);
            profileTabs->setVisible(index<2 || index==3);
            if(index==1) {configureNotepad(); showNotepad(); updateSelection(); QTimer::singleShot(0,this,[this] {if(unlocked && !pending && tabs->currentIndex()==1) refreshDocuments();});}
            if(index==2) populateProfileManager();
            if(index==3) QTimer::singleShot(0,this,[this] {if(unlocked && !pending && tabs->currentIndex()==3) refreshDocuments();});
            if(index==5) QTimer::singleShot(0,this,[this] {if(unlocked && !pending && tabs->currentIndex()==5) refreshProtectionStatus();});
        });
        connect(profileTabs,&QTabBar::currentChanged,this,[this](int index) {
            if(index<0) return;
            if(index==profileTabs->count()-1) {
                {QSignalBlocker block(profileTabs); profileTabs->setCurrentIndex(profileTabIndex(activeProfile));}
                if(unlocked && !pending) createProfileDialog();
                return;
            }
            if(pending) {QSignalBlocker block(profileTabs); profileTabs->setCurrentIndex(profileTabIndex(activeProfile)); return;}
            selectProfile(profileTabs->tabData(index).toString());
        });
        navigationButtons.first()->setChecked(true); tabs->setCurrentIndex(0);
        layout->addWidget(workspaceBody,1);
        sessionWarning = new QLabel; sessionWarning->setWordWrap(true); layout->addWidget(sessionWarning);
        applyPreferences({}); root->addWidget(sessionPage);
    }

    void buildAutomation() {
        auto* page=new QWidget;auto* layout=new QVBoxLayout(page);auto* title=new QLabel("Automation");title->setStyleSheet("font-size: 20px; font-weight: 600;");layout->addWidget(title);workflowEditor=new WorkflowEditor;layout->addWidget(workflowEditor,1);vaultMutationControls.append(workflowEditor);
        workflowEditor->onSave=[this](const QJsonArray& presets){auto value=preferences;value.insert("workflows",presets);request("settings_set",{{"preferences",value}},[this](bool ok,const QJsonObject& data){if(ok){workflowEditor->load(data.value("preferences").toObject().value("workflows").toArray(),true);applyPreferences(data.value("preferences").toObject());statusBar()->showMessage("Workflows saved inside this vault.");}});};
        auto* hint=new QLabel("Load a saved workflow in Notepad, choose Input, Output or Batch files, then Execute. Batch setup previews every destination. Each completed job opens a separate result window.");hint->setWordWrap(true);layout->addWidget(hint);tabs->addTab(page,"Automation");
    }

    void buildSettingsPage() {
        auto* page=new QWidget; auto* outer=new QVBoxLayout(page); auto* scroll=new QScrollArea; scroll->setWidgetResizable(true); auto* content=new QWidget; auto* layout=new QVBoxLayout(content); scroll->setWidget(content); outer->addWidget(scroll);
        auto* title=new QLabel("Vault settings"); title->setStyleSheet("font-size: 20px; font-weight: 600;"); layout->addWidget(title);
        readOnlySettingsNote=new QLabel; readOnlySettingsNote->setWordWrap(true); readOnlySettingsNote->hide(); layout->addWidget(readOnlySettingsNote);
        auto* hint=new QLabel("Themes, locking, clipboard expiry and Qubes requests are saved inside this vault."); hint->setWordWrap(true); layout->addWidget(hint);
        rememberVaultsCheck=new QCheckBox("Remember recent vaults on this device"); layout->addWidget(rememberVaultsCheck);
        recentStorageHint=new QLabel; recentStorageHint->setWordWrap(true); layout->addWidget(recentStorageHint);
        connect(rememberVaultsCheck,&QCheckBox::toggled,this,[this](bool enabled) {setRememberVaults(enabled);}); updateRecentVaultUi();
        auto* panel=buildPreferencesPanel(); layout->addWidget(panel); vaultMutationControls.append(panel);
        auto* convert=new QPushButton("Save converted vault copy…"); convert->setMinimumHeight(40); layout->addWidget(convert); connect(convert,&QPushButton::clicked,this,[this] {convertVault();}); vaultMutationControls.append(convert);
        auto* protection=new QGroupBox("Password and vault protection"); auto* protectionLayout=new QVBoxLayout(protection);
        protectionMasterCheck=new QCheckBox("Enable advanced vault protection"); protectionMasterCheck->setEnabled(false); protectionLayout->addWidget(protectionMasterCheck);
        auto* warning=new QLabel("Off by default. Enable this section before configuring alternative passwords or inactivity destruction. Disabling it erases all option settings. Enable each option, then set its password or period to activate it."); warning->setWordWrap(true); protectionLayout->addWidget(warning);
        const QStringList names{"Dummy password","Emergency destruction password","Delete after inactivity"};
        const QStringList options{"dummy","emergency","expiry"};
        for(int index=0;index<names.size();++index) {
            auto* row=new QHBoxLayout; auto* check=new QCheckBox(names[index]); check->setProperty("option",options[index]); check->setEnabled(false); row->addWidget(check,1); protectionOptionChecks.append(check);
            auto* control=new QPushButton(index==2?"Set period…":"Set / reset password…"); control->setMinimumHeight(38); control->setEnabled(false); row->addWidget(control); protectionOptionControls.append(control); protectionLayout->addLayout(row);
            connect(check,&QCheckBox::toggled,this,[this,index](bool enabled) {setProtectionOption(index,enabled);});
            connect(control,&QPushButton::clicked,this,[this,index] {if(index==0) dummyPasswordDialog(); else if(index==1) emergencyPasswordDialog(); else expiryDialog();});
        }
        auto* setupHint=new QLabel("A checked option permits setup; it becomes active only after you save a password or period. Fields always open blank and do not reveal previous setup. Turning an option off erases it; turning it on starts fresh."); setupHint->setWordWrap(true); protectionLayout->addWidget(setupHint);
        connect(protectionMasterCheck,&QCheckBox::toggled,this,[this](bool enabled) {setProtectionMaster(enabled);});
        vaultMutationControls.append(protection); layout->addWidget(protection);
        auto* portability=new QLabel("Conversion to either age v1 or KDBX 4.1 copies vault contents and preferences. Neither destination inherits PGPCrypt's adjacent dummy-password, emergency-destruction or inactivity records; configure those separately. KeePassXC can read KDBX contents but does not enforce these options."); portability->setWordWrap(true); layout->addWidget(portability);
        layout->addStretch(); tabs->addTab(page,"Vault settings");
    }

    void applyProtectionStatus(const QJsonObject& data,bool loaded) {
        protectionLoaded=loaded; protectionMaster=loaded && data.value("enabled").toBool(); protectionOptions=data;
        {QSignalBlocker block(protectionMasterCheck); protectionMasterCheck->setChecked(protectionMaster);}
        for(auto* check:protectionOptionChecks) {QSignalBlocker block(check); check->setChecked(protectionMaster && data.value(check->property("option").toString()+"_enabled").toBool());}
        applyReadOnlyUi();
    }

    void refreshProtectionStatus() {
        if(!unlocked || pending) return;
        if(sessionReadOnly) {applyProtectionStatus({},true); return;}
        request("protection_status",{},[this](bool ok,const QJsonObject& data) {applyProtectionStatus(data,ok);});
    }

    void setProtectionMaster(bool enabled) {
        if(sessionReadOnly || !protectionLoaded || pending) {QSignalBlocker block(protectionMasterCheck); protectionMasterCheck->setChecked(protectionMaster); return;}
        if(enabled && QMessageBox::warning(this,"Enable advanced vault protection","Some options permanently overwrite this vault copy. They do not guarantee secure erasure or plausible deniability. Companion records and file metadata can reveal their use; other applications and backups can bypass them.\n\nEnable only if you understand these limits. Each option starts off and requires fresh setup.",QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes) {QSignalBlocker block(protectionMasterCheck); protectionMasterCheck->setChecked(false); return;}
        request(enabled?"protection_enable":"protection_disable",{},[this,enabled](bool ok,const QJsonObject&) {
            const auto message=ok?(enabled?QString("Advanced protection enabled. Choose an option and set it up."):QString("Advanced protection off. All option settings were erased.")):statusBar()->currentMessage();
            request("protection_status",{},[this,message](bool loaded,const QJsonObject& data) {applyProtectionStatus(data,loaded); statusBar()->showMessage(message+(loaded?QString():QString(" Protection status is unknown.")));});
        });
    }

    void setProtectionOption(int index,bool enabled) {
        auto* check=protectionOptionChecks[index]; const auto option=check->property("option").toString();
        if(sessionReadOnly || !protectionLoaded || !protectionMaster || pending) {QSignalBlocker block(check); check->setChecked(protectionOptions.value(option+"_enabled").toBool()); return;}
        request(enabled?"protection_option_enable":"protection_option_disable",{{"protection_option",option}},[this,enabled](bool ok,const QJsonObject&) {
            const auto message=ok?(enabled?QString("Option enabled for setup. Save a new password or period to activate it."):QString("Option disabled and its settings erased.")):statusBar()->currentMessage();
            request("protection_status",{},[this,message](bool loaded,const QJsonObject& data) {applyProtectionStatus(data,loaded); statusBar()->showMessage(message);});
        });
    }

    void applyReadOnlyUi() {
        for(auto* control:vaultMutationControls) control->setEnabled(!sessionReadOnly && (!control->property("requiresOutput").toBool() || (output && !output->toPlainText().isEmpty())));
        if(profileTabs && profileTabs->count()>0) profileTabs->setTabEnabled(profileTabs->count()-1,!sessionReadOnly);
        syncNotepadProfiles();
        if(readOnlySettingsNote) readOnlySettingsNote->hide();
        if(protectionMasterCheck) protectionMasterCheck->setEnabled(!sessionReadOnly && protectionLoaded);
        for(int i=0;i<protectionOptionControls.size();++i) {const bool allowed=!sessionReadOnly && protectionLoaded && protectionMaster; protectionOptionChecks[i]->setEnabled(allowed); protectionOptionControls[i]->setEnabled(allowed && protectionOptionChecks[i]->isChecked());}
        if(documentContext) updateDocumentContext();
        if(settingsAction) settingsAction->setEnabled(unlocked && !sessionReadOnly);
        if(convertAction) convertAction->setEnabled(unlocked && !sessionReadOnly);
        if(sessionWarning) sessionWarning->setText("Vault unlocked. Press Ctrl+L to lock.");
    }

    void configureQubes() {
        if(!qubesEnabled || !unlocked || ending) {rpcServer.close(); if(!rpcPath.isEmpty()) {QLocalServer::removeServer(rpcPath); rpcPath.clear();} return;}
        if(rpcServer.isListening()) return;
        const QString parent=testing?QDir::homePath():"/run/user/"+QString::number(geteuid());
        const QString directory=parent+"/pgpcrypt";
        struct stat metadata{};
        if(::lstat(parent.toUtf8().constData(),&metadata)!=0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid!=geteuid() || (metadata.st_mode&0077)!=0) {fail("Qubes RPC needs a private /run/user runtime directory"); return;}
        if(::mkdir(directory.toUtf8().constData(),0700)!=0 && errno!=EEXIST) {fail("Cannot create Qubes broker directory"); return;}
        if(::lstat(directory.toUtf8().constData(),&metadata)!=0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid!=geteuid() || (metadata.st_mode&0077)!=0) {fail("Unsafe Qubes broker directory"); return;}
        const auto endpoint=directory+"/rpc.sock";
        // Never unlink an active broker belonging to another vault session.
        if(QFileInfo::exists(endpoint)) {fail("A Qubes broker already exists; close the other session (or remove a stale socket after confirming it is stopped)"); return;}
        rpcServer.setSocketOptions(QLocalServer::UserAccessOption); rpcServer.setMaxPendingConnections(4);
        if(!rpcServer.listen(endpoint)) {fail("Cannot listen for Qubes requests"); return;} rpcPath=endpoint;
    }

    void acceptQubes() {
        while(rpcServer.hasPendingConnections()) {
            auto* socket=rpcServer.nextPendingConnection(); if(!socket) return;
            if(++rpcConnections>4) {--rpcConnections; socket->abort(); socket->deleteLater(); continue;}
            connect(socket,&QLocalSocket::disconnected,this,[this,socket] {--rpcConnections; socket->deleteLater();});
            struct ucred credentials{}; socklen_t length=sizeof(credentials);
            if(::getsockopt(socket->socketDescriptor(),SOL_SOCKET,SO_PEERCRED,&credentials,&length)!=0 || credentials.uid!=geteuid()) {socket->disconnectFromServer(); continue;}
            auto buffer=std::make_shared<QByteArray>();
            auto* deadline=new QTimer(socket); deadline->setSingleShot(true); deadline->start(5000);
            connect(deadline,&QTimer::timeout,socket,[socket] {socket->abort();});
            connect(socket,&QLocalSocket::readyRead,this,[this,socket,buffer,deadline] {
                buffer->append(socket->readAll());
                if(buffer->size()>1024*1024+1024) {buffer->fill('\0'); socket->abort(); return;}
                if(!buffer->endsWith('\n')) return;
                deadline->stop(); socket->disconnect(socket,&QLocalSocket::readyRead,this,nullptr);
                QJsonParseError error; auto object=QJsonDocument::fromJson(*buffer,&error).object(); buffer->fill('\0'); buffer->clear();
                if(error.error!=QJsonParseError::NoError || object.value("version").toInt()!=1) {socket->abort(); return;}
                const auto operation=object.value("operation").toString(); const auto caller=object.value("caller").toString();
                bool validCaller=!caller.isEmpty() && caller.size()<=31 && caller.front().isLetter() && caller.front().unicode()<128;
                for(const auto character:caller) validCaller=validCaller && (character.unicode()<128) && (character.isLetterOrNumber() || character=='_' || character=='-');
                QSet<QString> allowed{"version","operation","caller"}; if(operation=="sign") allowed.insert("fingerprint"); if(operation=="sign" || operation=="decrypt") allowed.insert("text");
                for(auto i=object.begin();i!=object.end();++i) if(!allowed.contains(i.key())) validCaller=false;
                if(!validCaller || !unlocked || !qubesEnabled || ending) {socket->abort(); return;}
                auto reply=[socket](bool ok,const QJsonObject& data) {
                    if(socket->state()==QLocalSocket::UnconnectedState) return;
                    QJsonObject result{{"ok",ok}};
                    if(ok) {
                        QJsonObject remoteData;
                        for(const auto& key:QStringList{"text","signers"}) if(data.contains(key)) remoteData.insert(key,data.value(key));
                        result.insert("data",remoteData);
                    } else result.insert("error","Request denied, cancelled or failed");
                    auto bytes=QJsonDocument(result).toJson(QJsonDocument::Compact); bytes.append('\n');
                    if(bytes.size()>MaxRemoteFrame) {bytes.fill('\0'); bytes="{\"ok\":false,\"error\":\"Request denied, cancelled or failed\"}\n";}
                    socket->write(bytes); bytes.fill('\0'); socket->disconnectFromServer();
                };
                if(operation=="lock") {if(caller!="dom0" || !sessionLock) {reply(false,{}); return;} endSession(true); reply(ending,{}); socket->waitForBytesWritten(1000); return;}
                if(caller=="dom0" || (operation!="sign" && operation!="decrypt") || !object.value("text").isString() || object.value("text").toString().toUtf8().size()>1024*1024 || rpcBusy || pending || workflowRunning) {reply(false,{}); return;}
                const auto fp=object.value("fingerprint").toString();
                if(operation=="sign" && (signingChoice->findData(fp)<1 || fp.isEmpty())) {reply(false,{}); return;}
                if(rpcRate.isValid() && rpcRate.elapsed()<1000) {reply(false,{}); return;} rpcRate.start();
                rpcBusy=true;
                QDialog dialog(this); dialog.setWindowTitle("Approve Qubes request"); dialog.setMinimumSize(650,420);
                auto* layout=new QVBoxLayout(&dialog); auto* identity=new QLabel("From Qube: "+caller+"\nAction: "+operation+"\n"+(operation=="sign"?"Signing fingerprint: "+fp:"Decrypted text will be returned to this Qube.")); identity->setTextFormat(Qt::PlainText); identity->setWordWrap(true); layout->addWidget(identity);
                auto* preview=editor(operation=="sign"?"Signing content":"Encrypted content",true); preview->setPlainText(object.value("text").toString()); layout->addWidget(preview);
                auto* buttons=new QDialogButtonBox(QDialogButtonBox::Yes|QDialogButtonBox::Cancel); buttons->button(QDialogButtonBox::Yes)->setText("Approve "+operation); layout->addWidget(buttons);
                connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
                QTimer promptDeadline; promptDeadline.setSingleShot(true); promptDeadline.start(60000); connect(&promptDeadline,&QTimer::timeout,&dialog,&QDialog::reject);
                connect(socket,&QLocalSocket::disconnected,&dialog,&QDialog::reject);
                QPointer<QLocalSocket> guard(socket);
                if(testing) QTimer::singleShot(0,&dialog,caller=="work-mail"?&QDialog::accept:&QDialog::reject);
                if(dialog.exec()!=QDialog::Accepted || ending || !guard || socket->state()!=QLocalSocket::ConnectedState) {rpcBusy=false; if(guard) reply(false,{}); return;}
                QJsonObject fields{{"text",object.value("text")},{"profile_id",activeProfile}}; if(operation=="sign") fields.insert("fingerprint",fp);
                performCrypto(operation,fields,[this,guard,reply](bool ok,const QJsonObject& data) {rpcBusy=false; if(guard) reply(ok,data);},0,guard,true);
            });
        }
    }

    void applyPreferences(const QJsonObject& value) {
        preferences=value;
        autoLock=value.value("auto_lock").toBool(); focusLock=value.value("lock_on_focus_loss").toBool(); sessionLock=value.value("lock_on_session_events").toBool();
        clipboardSeconds=value.value("clipboard_clear_seconds").toInt(); qubesEnabled=!sessionReadOnly && value.value("qubes_rpc").toBool();
        notepadPopout=value.value("notepad_popout").toBool(false);
        activityClock.restart(); lastTick=QDateTime::currentMSecsSinceEpoch();
        const auto theme=value.value("theme").toString("light");
        qApp->setStyle(QStyleFactory::create("Fusion"));
        QPalette palette=qApp->style()->standardPalette();
        QColor background, base, text, accent, muted;
        bool custom=true;
        if(theme=="dark") {background="#24272e"; base="#191c22"; text="#e6e6e6"; accent="#568dcc"; muted="#9aa4b3";}
        else if(theme=="nord") {background="#2e3440"; base="#242933"; text="#eceff4"; accent="#5e81ac"; muted="#a8b2c4";}
        else if(theme=="warm-light") {background="#f3eee5"; base="#fffaf1"; text="#342e27"; accent="#99632f"; muted="#756b5b";}
        else if(theme=="solarized-light") {background="#eee8d5"; base="#fdf6e3"; text="#586e75"; accent="#006b98"; muted="#657b83";}
        else if(theme=="solarized" || theme=="solarized-dark") {background="#002b36"; base="#073642"; text="#93a1a1"; accent="#268bd2"; muted="#839496";}
        else if(theme=="ruby-dark") {background="#29151f"; base="#190e15"; text="#ffe8ee"; accent="#aa3159"; muted="#cca2b2";}
        else if(theme=="ruby-light") {background="#f7e8ed"; base="#fff8fa"; text="#451629"; accent="#a22750"; muted="#885a6a";}
        else if(theme=="terminal-green") {background="#09120c"; base="#030805"; text="#7cf79b"; accent="#167a3a"; muted="#65a879";}
        else if(theme=="cyberpunk") {background="#20152f"; base="#100d1d"; text="#f5e9ff"; accent="#ab227c"; muted="#b79cca";}
        else custom=false;
        if(custom) {
            palette.setColor(QPalette::Window,background); palette.setColor(QPalette::WindowText,text); palette.setColor(QPalette::Base,base); palette.setColor(QPalette::AlternateBase,background);
            palette.setColor(QPalette::Text,text); palette.setColor(QPalette::Button,background); palette.setColor(QPalette::ButtonText,text); palette.setColor(QPalette::Highlight,accent); palette.setColor(QPalette::HighlightedText,Qt::white);
            palette.setColor(QPalette::ToolTipBase,base); palette.setColor(QPalette::ToolTipText,text); palette.setColor(QPalette::PlaceholderText,muted);
            for(auto role:{QPalette::Text,QPalette::WindowText,QPalette::ButtonText}) palette.setColor(QPalette::Disabled,role,muted);
            palette.setColor(QPalette::Link,accent);
            palette.setColor(QPalette::Mid,background.lighter(145)); palette.setColor(QPalette::Midlight,background.lighter(120));
            palette.setColor(QPalette::Dark,base.darker(125)); palette.setColor(QPalette::Light,background.lighter(160)); palette.setColor(QPalette::Shadow,base.darker(160));
        }
        qApp->setPalette(palette);
        // Styled item views cache palette() colors. Refresh them after theme
        // changes so tables and lists follow the same theme as the editors.
        for(auto* widget:findChildren<QWidget*>()) if(!widget->styleSheet().isEmpty()) {
            const auto sheet=widget->styleSheet(); widget->setPalette(palette); widget->setStyleSheet({}); widget->setStyleSheet(sheet);
        }
        clipboardTimer.stop(); selectionTimer.stop();
        if(clipboardSeconds>0) { if(sessionClipboard()) clipboardTimer.start(clipboardSeconds*1000); if(sessionClipboard(QClipboard::Selection)) selectionTimer.start(clipboardSeconds*1000); }
        if(sessionWarning) sessionWarning->setText("Vault unlocked. Press Ctrl+L to lock.");
        activityClearTimer.stop(); const auto clearSeconds=value.value("activity_clear_seconds").toInt(); if(unlocked && clearSeconds>0) activityClearTimer.start(clearSeconds*1000);
        if(activityWelcome) {activityWelcome->setPlainText(value.value("activity_welcome").toString()); activityWelcome->setVisible(!activityWelcome->toPlainText().isEmpty()); activityWelcome->setFixedHeight(qMin(85,qMax(32,activityWelcome->document()->blockCount()*activityWelcome->fontMetrics().height()+14)));}
        refreshWorkflowChoices();
        if(syncSettingsControls) syncSettingsControls();
        updateSessionStats();
        configureNotepad(); configureQubes();
    }

    void wireClipboard() {
        clipboardTimer.setSingleShot(true); selectionTimer.setSingleShot(true);
        const auto changed=[this](QClipboard::Mode mode,QTimer& timer) {
            timer.stop();
            if(!sessionClipboard(mode)) qApp->setProperty(clipboardDigestProperty(mode),QVariant());
            else if(clipboardSeconds>0) timer.start(clipboardSeconds*1000);
        };
        connect(qApp->clipboard(),&QClipboard::dataChanged,this,[this,changed] {changed(QClipboard::Clipboard,clipboardTimer);});
        connect(qApp->clipboard(),&QClipboard::selectionChanged,this,[this,changed] {changed(QClipboard::Selection,selectionTimer);});
        connect(&clipboardTimer,&QTimer::timeout,this,[] {clearSessionClipboard();});
        connect(&selectionTimer,&QTimer::timeout,this,[] {clearSessionClipboard(QClipboard::Selection);});
    }

    void resetActivity() {if(activityLog) {activityLog->clear(); activityLog->record(ActivityEvent::SessionReady);}}
    void syncBusyUi() {
        const bool enabled=!pending && !workflowRunning && !ending;
        tabs->setEnabled(enabled); if(workspaceBody) workspaceBody->setEnabled(enabled); if(notepadPage) notepadPage->setEnabled(enabled); if(notepadProfileTabs) notepadProfileTabs->setEnabled(enabled);
        if(!activeBatch) for(const auto& window:jobWindows) if(window) for(auto* button:window->findChildren<QPushButton*>()) if(button->property("batchStop").toBool()) button->setEnabled(false);
    }
    QString activityKey(const QJsonObject& key) const {
        const auto fp=key.value("fingerprint").toString();
        if(!QRegularExpression("^(?:[A-F0-9]{40}|[A-F0-9]{64})$").match(fp).hasMatch()) return {};
        return "Key: "+SafeActivityLog::field(keyIdentity(key),120)+" ["+fp+"]";
    }
    QStringList activityContext(const QString& operation,const QJsonObject& fields) const {
        QStringList details;
        if(operation!="encrypt" && operation!="decrypt" && fields.contains("fingerprint")) {
            auto key=keyRecord(fields.value("fingerprint").toString()); if(key.isEmpty()) key.insert("fingerprint",fields.value("fingerprint")); const auto label=activityKey(key); if(!label.isEmpty()) details.append(label);
        }
        for(const auto& field:QStringList{"signing_keys","key_fingerprints"}) for(const auto& fp:fields.value(field).toArray()){const auto label=activityKey(keyRecord(fp.toString()));if(!label.isEmpty())details.append(label);}
        if(operation=="encrypt") for(const auto& fp:fields.value("recipients").toArray()) {const auto label=activityKey(keyRecord(fp.toString())); if(!label.isEmpty()) details.append(label);}
        if(operation.startsWith("document_")) {
            QString title=fields.value("title").toString(); const auto id=fields.value("document_id").toString();
            if(title.isEmpty() && documents) for(int row=0;row<documents->rowCount();++row) if(documents->item(row,0)->data(Qt::UserRole).toString()==id) {title=documents->item(row,0)->text(); break;}
            if(!title.isEmpty()) details.append("Document: "+SafeActivityLog::field(title));
        }
        if(operation=="profile_save" || operation=="profile_delete") {
            const auto id=fields.value("profile_id").toString(); QString title=fields.value("profile_name").toString();
            if(title.isEmpty()) for(const auto& value:profiles) {const auto profile=value.toObject(); if(profile.value("id").toString()==id) {title=profile.value("name").toString(); break;}}
            if(!title.isEmpty()) details.append("Identity: "+SafeActivityLog::field(title));
        }
        if(operation=="protect_private_key") details.append(QString("Private-key password protection: ")+(fields.value("new_password").toString().isEmpty()?"removed":"enabled"));
        if(operation=="settings_set") {
            const auto next=fields.value("preferences").toObject();
            const QList<QPair<QString,QString>> flags{{"auto_lock","Inactivity lock"},{"lock_on_focus_loss","Focus-loss lock"},{"lock_on_session_events","Desktop/Qubes lock events"},{"clipboard_clear_seconds","Clipboard timer"},{"theme","Theme"},{"qubes_rpc","Qubes requests"},{"notepad_popout","Detached Notepad"},{"activity_clear_seconds","Activity timer"},{"show_session_stats","Window counters"},{"allow_removable_media","Removable message files"}};
            for(const auto& item:flags) if(next.contains(item.first) && next.value(item.first)!=preferences.value(item.first)) {const auto value=next.value(item.first); details.append(item.second+": "+(value.isBool()?(value.toBool()?"on":"off"):value.isDouble()?(value.toInt()==0?QString("off"):QString::number(value.toInt())+" seconds"):SafeActivityLog::field(value.toString())));}
            if(next.contains("workflows") && next.value("workflows")!=preferences.value("workflows")) details.append("Workflows saved: "+QString::number(next.value("workflows").toArray().size()));
            if(next.contains("activity_welcome") && next.value("activity_welcome")!=preferences.value("activity_welcome")) details.append(QString("Welcome block: ")+(next.value("activity_welcome").toString().isEmpty()?"hidden":"shown"));
            if(fields.contains("idle_timeout_seconds") && fields.value("idle_timeout_seconds").toInt()!=idleTimeoutSeconds) details.append("Inactivity timeout: "+QString::number(fields.value("idle_timeout_seconds").toInt())+" seconds");
            if(fields.contains("default_signing_key")) {const auto key=activityKey(keyRecord(fields.value("default_signing_key").toString())); details.append(key.isEmpty()?QString("Default signing key cleared"):"Default signer: "+key);}
        }
        if(workflowRunning && activeWorkflow) details.append("Workflow: "+SafeActivityLog::field(activeWorkflow->name)+"; step "+QString::number(activeWorkflow->index+1));
        details.removeAll(QString()); return details;
    }
    QString activityReason(const QString& diagnostic,const QString& code) const {
        if(code=="password_required" || code=="vault_auth_required") return "Authorization was not completed; no key material was released.";
        if(code=="verification_failed") return "Signature invalid, unsupported, changed, or signer missing from this profile.";
        const QHash<QString,QString> reasons{{"storage_permission","Permission denied; choose a writable folder and check file ownership."},{"storage_missing","A required file or folder is missing."},{"storage_exists","The destination already exists; choose a new filename."},{"storage_full","Storage is full; free space before retrying."},{"storage_read_only","The destination filesystem is read-only."},{"key_generation","Key generation failed; check the name, algorithm, capabilities and expiry."},{"key_import","Key import failed; paste one complete supported armored certificate."},{"subkey_configuration","Subkeys were not saved; check primary private-key access, purpose, algorithm and expiries."},{"signing_key","Signing failed; select a usable signing key and check its expiry and password."},{"encryption_selection","Encryption failed; check recipients, key capabilities/expiry and the 1 MiB plaintext limit."},{"decryption_authentication","Decryption failed; check the message, available private keys, password and authentication."},{"settings_or_save","Settings were not saved; check values, storage permissions and available space."},{"identity_or_save","Identity changes were not saved; check fields and storage."},{"document_or_save","Document action failed; check the selected document, size and storage."}};
        return reasons.value(diagnostic,"Operation failed; see the status message for more detail.");
    }
    void updateSessionStats() {
        if(!sessionStats) return;
        sessionStats->setVisible(unlocked);
        qint64 subkeys=0,notes=0; for(const auto& key:cachedKeys) subkeys+=key.toObject().value("subkey_count").toInteger(); for(const auto& count:profileDocumentCounts) notes+=count.toInteger();
        QString text=QString("KEYS %1   SUBKEYS %2   IDENTITIES %3   NOTES %4   WORKFLOWS %5").arg(cachedKeys.size()).arg(subkeys).arg(profiles.size()).arg(notes).arg(preferences.value("workflows").toArray().size());
        if(preferences.value("show_session_stats").toBool()) {const auto seconds=sessionClock.isValid()?sessionClock.elapsed()/1000:0; text+=QString("\nUNLOCKED %1m %2s   COMPLETED ACTIONS %3   FAILED OPENS BEFORE UNLOCK %4").arg(seconds/60).arg(seconds%60).arg(sessionOperations).arg(failedOpens);}
        sessionStats->setText(text); sessionStats->setToolTip("Inventory includes this vault's complete collection, including expired subkeys. Counters exist only in this window process: locking the vault or closing/restarting PGPCrypt resets them. Failed opens include password and file errors before successful unlock; no history survives a reboot.");
    }

    QWidget* buildPreferencesPanel() {
        auto* panel=new QGroupBox("Appearance and session security"); auto* form=new QFormLayout(panel);
        auto* theme=new QComboBox;
        const QList<QPair<QString,QString>> themes{{"Light","light"},{"Warm light","warm-light"},{"Dark","dark"},{"Nord","nord"},{"Solarized light","solarized-light"},{"Solarized dark","solarized-dark"},{"Ruby dark","ruby-dark"},{"Ruby light","ruby-light"},{"Hacker green","terminal-green"},{"Cyberpunk","cyberpunk"}};
        for(const auto& entry:themes) theme->addItem(entry.first,entry.second);
        form->addRow("Theme",theme);
        auto* popout=new QCheckBox("Open Notepad in its own window"); form->addRow(popout);
        auto* enable=new QCheckBox("Lock after inactivity"); form->addRow(enable);
        auto* minutes=new QSlider(Qt::Horizontal); minutes->setRange(1,60); auto* minuteLabel=new QLabel;
        auto* row=new QHBoxLayout; row->addWidget(minutes); row->addWidget(minuteLabel); form->addRow("Inactivity timeout",row);
        connect(enable,&QCheckBox::toggled,minutes,&QWidget::setEnabled); connect(minutes,&QSlider::valueChanged,panel,[=](int value) {minuteLabel->setText(QString::number(value)+" minutes");});
        auto* focus=new QCheckBox("Lock when switching away from PGPCrypt"); form->addRow(focus);
        auto* events=new QCheckBox("Lock on desktop events or an allowed Qubes lock request"); form->addRow(events);
        auto* eventHint=new QLabel("Desktop lock and suspend signals depend on your session. Qubes Lock requests require the documented dom0 hook and Qubes requests enabled below."); eventHint->setWordWrap(true); form->addRow(eventHint);
        auto* clip=new QCheckBox("Clear copied text after a delay"); form->addRow(clip);
        auto* seconds=new QSlider(Qt::Horizontal); seconds->setRange(5,1800); auto* secondLabel=new QLabel;
        auto* clipRow=new QHBoxLayout; clipRow->addWidget(seconds); clipRow->addWidget(secondLabel); form->addRow("Clipboard delay",clipRow);
        connect(clip,&QCheckBox::toggled,seconds,&QWidget::setEnabled); connect(seconds,&QSlider::valueChanged,panel,[=](int value) {secondLabel->setText(QString("%1m %2s").arg(value/60).arg(value%60));});
        auto* clipHint=new QLabel("Lock always clears text still owned by PGPCrypt, even with this timer off. External clipboard history cannot be erased."); clipHint->setWordWrap(true); form->addRow(clipHint);
        auto* clearActivity=new QCheckBox("Periodically clear session activity"); form->addRow(clearActivity);
        auto* activitySeconds=new QSpinBox; activitySeconds->setRange(5,3600); activitySeconds->setSuffix(" seconds"); form->addRow("Activity clear interval",activitySeconds); connect(clearActivity,&QCheckBox::toggled,activitySeconds,&QWidget::setEnabled);
        auto* stats=new QCheckBox("Show unlock-attempt and action counters for this window"); form->addRow(stats);
        auto* statsHint=new QLabel("Counters are kept only until this vault locks or this window closes/restarts, including a reboot. Failed opens are shown after successful unlock and can include password or file errors. Inventory counts always appear above Session activity. No login history is saved."); statsHint->setWordWrap(true); form->addRow(statsHint);
        auto* welcome=new QPlainTextEdit; welcome->setObjectName("activityWelcomeSetting"); welcome->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont)); welcome->setMaximumHeight(95); welcome->setPlaceholderText("Optional welcome text or ASCII art (16 lines / 2 KiB). Stored inside this vault."); form->addRow("Activity welcome block",welcome);
        auto* usb=new QCheckBox("Allow removable media for message import and export"); form->addRow(usb);
        auto* usbHint=new QLabel("Off hides USB/removable mounts in the message picker and blocks message reads/writes there. It does not disable OS automounting, other applications, or opening a vault stored on a USB device."); usbHint->setWordWrap(true); form->addRow(usbHint);
        memoryStatus=new QLabel; memoryStatus->setTextFormat(Qt::PlainText); memoryStatus->setWordWrap(true); form->addRow("Worker memory",memoryStatus);
        auto* qubes=new QCheckBox("Allow requests from other Qubes while unlocked"); form->addRow(qubes);
        auto* qubesHint=new QLabel("A named-client dom0 policy is required. You approve each signing/decryption request here; private keys stay in this Qube. Setup: /usr/share/doc/pgpcrypt/design/QUBES.md"); qubesHint->setWordWrap(true); form->addRow(qubesHint);
        auto* save=new QPushButton("Save preferences"); form->addRow(save);
        connect(save,&QPushButton::clicked,this,[=,this] {
            QJsonObject value{{"auto_lock",enable->isChecked()},{"lock_on_focus_loss",focus->isChecked()},{"lock_on_session_events",events->isChecked()},{"clipboard_clear_seconds",clip->isChecked()?seconds->value():0},{"theme",theme->currentData().toString()},{"qubes_rpc",qubes->isChecked()},{"notepad_popout",popout->isChecked()},{"activity_clear_seconds",clearActivity->isChecked()?activitySeconds->value():0},{"show_session_stats",stats->isChecked()},{"allow_removable_media",usb->isChecked()}};
            value.insert("activity_welcome",welcome->toPlainText()); value.insert("workflows",preferences.value("workflows").toArray());
            request("settings_set",{{"idle_timeout_seconds",minutes->value()*60},{"preferences",value}},[this](bool ok,const QJsonObject& data) {if(ok) {idleTimeoutSeconds=data.value("idle_timeout_seconds").toInt(300); applyPreferences(data.value("preferences").toObject()); statusBar()->showMessage("Preferences saved in this vault.");}});
        });
        syncSettingsControls=[=,this] {
            auto savedTheme=preferences.value("theme").toString("light"); if(savedTheme=="solarized") savedTheme="solarized-dark"; theme->setCurrentIndex(qMax(0,theme->findData(savedTheme)));
            popout->setChecked(notepadPopout); enable->setChecked(autoLock); minutes->setValue(idleTimeoutSeconds/60); minutes->setEnabled(autoLock); minuteLabel->setText(QString::number(minutes->value())+" minutes");
            focus->setChecked(focusLock); events->setChecked(sessionLock); clip->setChecked(clipboardSeconds>0); seconds->setValue(clipboardSeconds>0?clipboardSeconds:30); seconds->setEnabled(clipboardSeconds>0); secondLabel->setText(QString("%1m %2s").arg(seconds->value()/60).arg(seconds->value()%60));
            const auto interval=preferences.value("activity_clear_seconds").toInt(); clearActivity->setChecked(interval>0); activitySeconds->setValue(interval>0?interval:300); activitySeconds->setEnabled(interval>0); stats->setChecked(preferences.value("show_session_stats").toBool()); usb->setChecked(preferences.value("allow_removable_media").toBool()); qubes->setChecked(qubesEnabled);
            welcome->setPlainText(preferences.value("activity_welcome").toString());
            const auto swap=workerSecurity.value("swap").toString("unknown");
            memoryStatus->setText((workerSecurity.value("selected_buffers_locked").toBool()?QString("Retained worker password pages locked. "):QString("Memory locking unavailable or limited. "))+(swap=="active"?QString("Swap is active; encryption is unknown. "):swap=="none"?QString("No active swap at worker startup. "):QString("Swap status unavailable. "))+"GUI and library copies are not all locked.");
        };
        return panel;
    }

    void buildKeys() {
        auto* page = new QWidget; auto* layout = new QVBoxLayout(page);
        search = new QLineEdit; search->setPlaceholderText("Filter identities or fingerprints…"); layout->addWidget(search);
        keys = new QTableWidget(0,9); configureKeyTable(keys,"Default"); installKeyMenu(keys); keys->setMinimumHeight(190); layout->addWidget(keys,2);
        keyStatus=new QComboBox; keyStatus->addItems({"All keys","Usable","Expired","Revoked","Private keys","Public only"}); layout->insertWidget(1,keyStatus);
        connect(keys->horizontalHeader(),&QHeaderView::sortIndicatorChanged,this,[this] {QTimer::singleShot(0,this,[this] {filterKeyTable(keys,search->text(),keyStatus->currentIndex());});});
        connect(search,&QLineEdit::textChanged,this,[this] {filterKeyTable(keys,search->text(),keyStatus->currentIndex());});
        connect(keyStatus,&QComboBox::currentIndexChanged,this,[this] {filterKeyTable(keys,search->text(),keyStatus->currentIndex());});
        details = new QLabel("Select a key to inspect its full fingerprint."); details->setTextFormat(Qt::PlainText); details->setTextInteractionFlags(Qt::TextSelectableByMouse); details->setWordWrap(true); layout->addWidget(details);
        connect(keys,&QTableWidget::itemSelectionChanged,this,[this] {
            const int row=keys->currentRow(); if(row<0) return;
            details->setText(keys->item(row,1)->text()+"\n"+keys->item(row,2)->text()+"\n"+keys->item(row,2)->data(Qt::UserRole+2).toString()+"\nCheck this fingerprint through an independent channel.");
        });
        auto* actions = new QHBoxLayout;
        auto* publicExport = new QPushButton("Show public export"); actions->addWidget(publicExport);
        connect(publicExport,&QPushButton::clicked,this,[this] {
            const int row=keys->currentRow(); if(row<0) { fail("Select a key"); return; }
            request("public_export",{{"fingerprint",keys->item(row,2)->text()}},[this](bool ok,const QJsonObject& data) { if(ok) { outputIsEncrypted=false; clearVerificationIdentity(); output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1); statusBar()->showMessage("Public export: publishing it exposes its identities"); } });
        });
        layout->addLayout(actions);
        auto* backupActions = new QHBoxLayout;
        auto* privateExport = new QPushButton("Show private key"); backupActions->addWidget(privateExport);
        connect(privateExport,&QPushButton::clicked,this,[this] {
            const int row=keys->currentRow(); if(row<0 || !keys->item(row,2)->data(Qt::UserRole+5).toBool()) { fail("Select a private key"); return; }
            const bool protectedKey=keys->item(row,2)->data(Qt::UserRole+3).toBool();
            const auto message=protectedKey?QString("Display the password-protected private key for backup? Copying it puts it outside the vault."):QString("This key contains private packets without password protection. Anyone who gets those packets can use them. Display it for backup?");
            if(QMessageBox::question(this,"Export private key",message) == QMessageBox::Yes)
                exportSelected("private_export");
        });
        auto* revocation = new QPushButton("Show revocation certificate"); backupActions->addWidget(revocation);
        connect(revocation,&QPushButton::clicked,this,[this] {
            if(QMessageBox::question(this,"Revocation certificate","Anyone with this certificate can revoke your key. Keep a private backup. Creating or displaying it does not revoke the key.") == QMessageBox::Yes)
                exportSelected("revocation_export");
        });
        auto* protect = new QPushButton("Set / change / remove key password…"); backupActions->addWidget(protect);
        connect(protect,&QPushButton::clicked,this,[this] { protectKeyDialog(); }); vaultMutationControls.append(protect);
        auto* subkeys=new QPushButton("Manage subkeys…"); backupActions->addWidget(subkeys);
        connect(subkeys,&QPushButton::clicked,this,[this] { subkeysDialog(); }); vaultMutationControls.append(subkeys);
        layout->addLayout(backupActions);
        auto* lower = new QTabWidget;
        auto* generatePage = new QWidget; auto* generateLayout = new QVBoxLayout(generatePage);
        auto* description = new QLabel("Create a key with optional email, comment and password. A revocation certificate is saved in the vault for emergencies.");
        description->setWordWrap(true); generateLayout->addWidget(description);
        auto* generate = new QPushButton("Create key…"); generateLayout->addWidget(generate); generateLayout->addStretch();
        connect(generate,&QPushButton::clicked,this,[this] { createKeyDialog(); });
        lower->addTab(generatePage,"New key");
        auto* importPage = new QWidget; auto* importLayout = new QVBoxLayout(importPage);
        importText=editor("Paste one armored public or private key…"); importLayout->addWidget(importText);
        auto* importButtons=new QHBoxLayout; auto* importButton = new QPushButton("Import into vault"); auto* clipboardImport=new QPushButton("Paste, clear clipboard and import"); clipboardImport->setObjectName("clipboardImport"); clipboardImport->setToolTip("Replaces this editor, clears the clipboard immediately, then imports. Clipboard managers may retain earlier copies."); importButtons->addWidget(importButton); importButtons->addWidget(clipboardImport); importLayout->addLayout(importButtons);
        connect(clipboardImport,&QPushButton::clicked,this,[this] {importClipboardKey();});
        connect(importButton,&QPushButton::clicked,this,[this] { request("import",{{"text",importText->toPlainText()},{"profile_id",activeProfile}},[this](bool ok,const QJsonObject&) { if(ok) { importText->clear(); refreshKeys(); } }); });
        lower->addTab(importPage,"Import key"); layout->addWidget(lower,1); vaultMutationControls.append(lower);
        tabs->addTab(page,"Keys");
    }

    void importClipboardKey(std::function<void()> after={}) {
        if(!unlocked || pending || workflowRunning || sessionReadOnly) return;
        QString text=qApp->clipboard()->text(); qApp->clipboard()->clear(); qApp->setProperty(clipboardDigestProperty(QClipboard::Clipboard),QVariant());
        if(qApp->clipboard()->supportsSelection() && qApp->clipboard()->text(QClipboard::Selection)==text) {qApp->clipboard()->clear(QClipboard::Selection); qApp->setProperty(clipboardDigestProperty(QClipboard::Selection),QVariant());}
        auto bytes=text.toUtf8(); const bool valid=!bytes.isEmpty() && bytes.size()<=1024*1024; bytes.fill('\0');
        if(!valid) {text.fill(QChar('\0')); fail("Clipboard cleared. Copy one armored key no larger than 1 MiB and try again."); if(activityLog) activityLog->record(ActivityEvent::OperationFailed,{"Clipboard import: empty or larger than 1 MiB; clipboard cleared."}); return;}
        importText->setPlainText(text); text.fill(QChar('\0'));
        request("import",{{"text",importText->toPlainText()},{"profile_id",activeProfile}},[this,after](bool ok,const QJsonObject&) {if(ok) {importText->clear(); refreshKeys([this,after] {statusBar()->showMessage("Key imported; clipboard cleared."); if(after) after();});}});
    }

    void exportSelected(const QString& operation) {
        const int row=keys->currentRow(); if(row<0) {fail("Select a key"); return;} exportKey(operation,keys->item(row,2)->text());
    }

    void subkeysDialog(const QString& selectedFingerprint = {}) {
        const int row=keys->currentRow(); if(selectedFingerprint.isEmpty() && row<0) {fail("Select a key"); return;}
        const auto fp=selectedFingerprint.isEmpty()?keys->item(row,2)->text():selectedFingerprint; const bool secret=!sessionReadOnly && keyRecord(fp).value("primary_secret_available").toBool() && keyRecord(fp).value("primary_can_certify").toBool() && keyRecord(fp).value("status").toString()=="Valid";
        request("subkeys",{{"fingerprint",fp}},[this,fp,secret](bool ok,const QJsonObject& data) {
            if(!ok) return;
            QDialog dialog(this); dialog.setWindowTitle("Primary key and subkeys"); dialog.resize(950,450); auto* layout=new QVBoxLayout(&dialog);
            auto* label=new QLabel("Primary fingerprint: "+fp+"\nSubkeys keep the same OpenPGP identity. Adding them requires a valid, unrevoked certification-capable primary private key, not just private subkeys."); label->setTextFormat(Qt::PlainText); label->setWordWrap(true); layout->addWidget(label);
            auto* table=new QTableWidget(0,6); styleTable(table); table->setSortingEnabled(false); table->setHorizontalHeaderLabels({"Role","Fingerprint","Algorithm","Capabilities","Expires","Status"}); table->setEditTriggers(QAbstractItemView::NoEditTriggers); layout->addWidget(table);
            for(const auto& value:data.value("keys").toArray()) {const auto key=value.toObject(); const int row=table->rowCount(); table->insertRow(row);
                QStringList fields{key.value("primary").toBool()?"Primary":"Subkey",key.value("fingerprint").toString(),key.value("algorithm").toString(),key.value("capabilities").toString(),key.value("expires_at").isNull()?"Never":QDateTime::fromSecsSinceEpoch(key.value("expires_at").toInteger(),QTimeZone::UTC).toString(Qt::ISODate),key.value("status").toString()};
                for(int column=0;column<fields.size();++column) table->setItem(row,column,new QTableWidgetItem(fields[column]));
            }
            table->resizeColumnsToContents(); table->setSortingEnabled(true); installCopyMenu(table); auto* add=new QPushButton("Add subkey…"); add->setEnabled(secret); layout->addWidget(add);
            connect(add,&QPushButton::clicked,&dialog,[&] {dialog.accept();});
            auto* close=new QDialogButtonBox(QDialogButtonBox::Close); layout->addWidget(close); connect(close,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
            if(dialog.exec()==QDialog::Accepted && !ending) addSubkeyDialog(fp);
        });
    }

    void addSubkeyDialog(const QString& fp) {
        if(!unlocked || pending || sessionReadOnly) return;
        const auto primary=keyRecord(fp); const qint64 expiry=primary.value("expires_at").toInteger();
        QDialog dialog(this); dialog.setWindowTitle("Add subkeys to existing key"); dialog.resize(840,570); auto* layout=new QVBoxLayout(&dialog);
        auto* label=new QLabel(activityKey(primary)+"\nThe primary private key must support certification. All rows commit together. Export the updated public key after saving."); label->setTextFormat(Qt::PlainText); label->setWordWrap(true); layout->addWidget(label);
        auto* plan=new SubkeyPlanner; plan->addRow("encrypt","cv25519",expiry); layout->addWidget(plan);
        auto* form=new QFormLayout; auto* pass=new QLineEdit; auto* confirm=new QLineEdit; for(auto* field:{pass,confirm}) {field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText); limitNewPassword(field);}
        form->addRow("Password for all new subkeys (optional)",pass); form->addRow("Confirm password",confirm); form->addRow(passwordStrength(pass)); layout->addLayout(form);
        auto* note=new QLabel("Leave the new password blank for unprotected subkey packets inside the encrypted vault. The primary key's existing password is requested separately only if needed."); note->setWordWrap(true); layout->addWidget(note);
        auto* error=new QLabel; error->setWordWrap(true); error->setTextFormat(Qt::PlainText); layout->addWidget(error); auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); layout->addWidget(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); connect(buttons,&QDialogButtonBox::accepted,&dialog,[&] {if(pass->text()!=confirm->text()) {error->setText("Passwords do not match."); return;} const auto issue=plan->validation(expiry); if(!issue.isEmpty()) {error->setText(issue); return;} dialog.accept();});
        if(dialog.exec()!=QDialog::Accepted) {pass->clear(); confirm->clear(); return;}
        QJsonObject fields{{"fingerprint",fp},{"subkey_batch",plan->plan()},{"new_password",pass->text()}}; pass->clear(); confirm->clear();
        performCrypto("add_subkeys",fields,[this](bool ok,const QJsonObject& data) {if(ok) {refreshKeys(); statusBar()->showMessage(QString::number(data.value("added").toInt())+" subkeys saved. Export and distribute the updated public key.");}});
    }

    void createKeyDialog() {
        QDialog dialog(this); dialog.setWindowTitle("Create OpenPGP key"); dialog.setMinimumWidth(680); dialog.resize(860,qMin(800,qApp->primaryScreen()->availableGeometry().height()-60));
        auto* layout=new QVBoxLayout(&dialog); auto* form=new QFormLayout;
        auto* name=new QLineEdit; auto* email=new QLineEdit; auto* comment=new QLineEdit;
        name->setMaxLength(128); email->setMaxLength(254); comment->setMaxLength(256);
        form->addRow("Name or pseudonym",name); form->addRow("Email (optional)",email); form->addRow("Public comment (optional)",comment);
        auto* disclosure=new QLabel("Email and comment appear in public-key exports. Leave them blank to avoid sharing them."); disclosure->setWordWrap(true); form->addRow(disclosure);
        auto* algorithm=new QComboBox;
        algorithm->addItem("Ed25519 / Cv25519 (recommended)","cv25519");
        algorithm->addItem("RSA 2048-bit","rsa2048"); algorithm->addItem("RSA 4096-bit","rsa4096");
        algorithm->addItem("ECDSA / ECDH NIST P-256","p256"); algorithm->addItem("ECDSA / ECDH NIST P-384","p384"); algorithm->addItem("ECDSA / ECDH NIST P-521","p521");
        form->addRow("Algorithm",algorithm);
        auto* keyLayout=new QComboBox; keyLayout->addItem("Primary key + separate signing/encryption subkeys","subkeys"); keyLayout->addItem("Single RSA key with selected capabilities","single"); keyLayout->setEnabled(false); form->addRow("Key layout",keyLayout);
        auto* certify=new QCheckBox("Certification (primary key)"); certify->setChecked(true); certify->setEnabled(false);
        auto* signing=new QCheckBox("Sign"); signing->setChecked(true);
        auto* transport=new QCheckBox("Encrypt messages and files"); transport->setChecked(true);
        auto* authentication=new QCheckBox("Authentication"); authentication->setChecked(true);
        authentication->setToolTip("For systems explicitly supporting OpenPGP authentication. It is not required for signing or encryption.");
        auto* capabilities=new QWidget; capabilities->setObjectName("keyCapabilities"); auto* capabilityLayout=new QVBoxLayout(capabilities); capabilityLayout->setContentsMargins(0,0,0,0); for(auto* check:{certify,signing,transport,authentication}) capabilityLayout->addWidget(check); form->addRow("Capabilities",capabilities);
        auto* capabilityHint=new QLabel("Encryption sets both OpenPGP transport and storage flags. Certification binds the identity and subkeys."); capabilityHint->setWordWrap(true); form->addRow(capabilityHint);
        auto updateLayout=[=] {
            const bool rsa=algorithm->currentData().toString().startsWith("rsa");
            keyLayout->setEnabled(rsa); if(!rsa) keyLayout->setCurrentIndex(0);
            const bool subkeys=keyLayout->currentData().toString()=="subkeys";
            certify->setEnabled(!subkeys); if(subkeys) certify->setChecked(true);
        };
        connect(algorithm,&QComboBox::currentIndexChanged,&dialog,updateLayout); connect(keyLayout,&QComboBox::currentIndexChanged,&dialog,updateLayout);
        auto* expire=new QCheckBox("Expire on"); expire->setObjectName("primaryExpiryEnabled"); expire->setChecked(false);
        auto* date=new QDateTimeEdit(QDateTime::currentDateTimeUtc().addYears(2)); date->setObjectName("primaryExpiry"); date->setCalendarPopup(true); date->setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'"); date->setEnabled(false);
        connect(expire,&QCheckBox::toggled,date,&QWidget::setEnabled); form->addRow(expire,date);
        auto* pass=new QLineEdit; auto* confirm=new QLineEdit;
        for(auto* field : {pass,confirm}) { field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase); }
        limitNewPassword(pass); limitNewPassword(confirm);
        form->addRow("Private-key password/passphrase (optional)",pass); form->addRow("Confirm password/passphrase",confirm); form->addRow(passwordStrength(pass));
        auto* custom=new QGroupBox("Plan subkeys individually (optional)"); custom->setObjectName("customSubkeys"); custom->setCheckable(true); custom->setChecked(false); auto* planLayout=new QVBoxLayout(custom); auto* plan=new SubkeyPlanner; plan->addRow("sign"); plan->addRow("encrypt"); plan->addRow("authenticate"); planLayout->addWidget(plan); plan->hide(); form->addRow(custom);
        auto updatePlan=[=] {const bool allowed=keyLayout->currentData().toString()=="subkeys"; custom->setEnabled(allowed); if(!allowed) custom->setChecked(false); const bool planned=allowed && custom->isChecked(); plan->setVisible(planned); for(auto* check:{signing,transport,authentication}) check->setEnabled(!planned); capabilityHint->setText(planned?"The rows below define subkeys; the primary key retains certification only.":"Encryption sets transport and storage flags. Certification binds the identity and subkeys.");};
        connect(custom,&QGroupBox::toggled,&dialog,updatePlan); connect(keyLayout,&QComboBox::currentIndexChanged,&dialog,updatePlan); connect(algorithm,&QComboBox::currentIndexChanged,&dialog,updatePlan);
        auto* scroll=new QScrollArea; scroll->setWidgetResizable(true); scroll->setFrameShape(QFrame::NoFrame); auto* fieldsWidget=new QWidget; fieldsWidget->setLayout(form); scroll->setWidget(fieldsWidget); layout->addWidget(scroll,1);
        auto* hint=new QLabel("Leave both passwords blank for no separate key password. A key password also protects private-key exports. Legacy keys can be imported."); hint->setWordWrap(true); layout->addWidget(hint);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); error->setWordWrap(true); layout->addWidget(error);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel); layout->addWidget(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        connect(buttons,&QDialogButtonBox::accepted,&dialog,[=,&dialog] {
            if(name->text().trimmed().isEmpty()) { error->setText("Enter a name or pseudonym."); return; }
            if(pass->text()!=confirm->text()) { error->setText("Passwords/passphrases do not match."); return; }
            if(!certify->isChecked() && !signing->isChecked() && !transport->isChecked() && !authentication->isChecked()) { error->setText("Select at least one capability."); return; }
            if(expire->isChecked() && date->dateTime() <= QDateTime::currentDateTimeUtc().addSecs(60)) { error->setText("Choose an expiry at least one minute in the future."); return; }
            if(custom->isChecked()) {const auto issue=plan->validation(expire->isChecked()?date->dateTime().toSecsSinceEpoch():0); if(!issue.isEmpty()) {error->setText(issue); return;}}
            dialog.accept();
        });
        if(dialog.exec()!=QDialog::Accepted) { pass->clear(); confirm->clear(); return; }
        QJsonObject options{{"name",name->text()},{"email",email->text()},{"comment",comment->text()},{"algorithm",algorithm->currentData().toString()},{"layout",keyLayout->currentData().toString()},
            {"certification",certify->isChecked()},{"signing",signing->isChecked()},{"transport_encryption",transport->isChecked()},{"storage_encryption",transport->isChecked()},{"authentication",authentication->isChecked()},
            {"expires_at",expire->isChecked()?QJsonValue(date->dateTime().toSecsSinceEpoch()):QJsonValue(QJsonValue::Null)}};
        if(custom->isChecked()) {options.insert("signing",false); options.insert("transport_encryption",false); options.insert("storage_encryption",false); options.insert("authentication",false);}
        QJsonObject fields{{"key_options",options},{"password",pass->text()}}; pass->clear(); confirm->clear();
        fields.insert("profile_id",activeProfile); if(custom->isChecked()) fields.insert("subkey_batch",plan->plan());
        request("generate",fields,[this](bool ok,const QJsonObject&) { if(ok) { refreshKeys(); statusBar()->showMessage("Key and revocation certificate saved in this profile."); } });
    }

    void protectKeyDialog(const QString& selectedFingerprint = {}) {
        const int row=keys->currentRow(); if(selectedFingerprint.isEmpty() && row<0) { fail("Select a private key"); return; }
        const QString fingerprint=selectedFingerprint.isEmpty()?keys->item(row,2)->text():selectedFingerprint;
        if(sessionReadOnly || !keyRecord(fingerprint).value("has_secret").toBool()) {fail("Action unavailable in this session."); return;}
        QDialog dialog(this); dialog.setWindowTitle("Private-key password"); auto* form=new QFormLayout(&dialog);
        auto* current=new QLineEdit; auto* pass=new QLineEdit; auto* confirm=new QLineEdit;
        for(auto* field : {current,pass,confirm}) { field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase); }
        limitNewPassword(pass); limitNewPassword(confirm); form->addRow(passwordStrength(pass));
        form->addRow("Current passphrase (if protected)",current); form->addRow("New password/passphrase (optional)",pass); form->addRow("Confirm new passphrase",confirm);
        auto* hint=new QLabel("Leave both new password fields blank to remove the key password. The vault remains encrypted."); hint->setWordWrap(true); form->addRow(hint);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); form->addRow(error);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel); form->addRow(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        connect(buttons,&QDialogButtonBox::accepted,&dialog,[=,&dialog] {
            if(pass->text()!=confirm->text()) { error->setText("Passwords/passphrases do not match."); return; }
            dialog.accept();
        });
        if(dialog.exec()!=QDialog::Accepted) { current->clear(); pass->clear(); confirm->clear(); return; }
        QJsonObject fields{{"fingerprint",fingerprint},{"password",current->text()},{"new_password",pass->text()}};
        current->clear(); pass->clear(); confirm->clear();
        request("protect_private_key",fields,[this](bool ok,const QJsonObject&) { if(ok) { refreshKeys(); statusBar()->showMessage("Private-key passphrase updated. Old exports and backups retain their previous protection."); } });
    }

    QJsonObject keyRecord(const QString& fingerprint) const {
        for(const auto& value:cachedKeys) if(value.toObject().value("fingerprint").toString()==fingerprint) return value.toObject();
        return {};
    }

    static QString tableRowText(QTableWidget* table,int row) {
        QStringList fields; for(int column=0;column<table->columnCount();++column) if(const auto* item=table->item(row,column)) fields.append(item->text()); return fields.join("\t");
    }

    void installCopyMenu(QTableWidget* table) {
        table->setContextMenuPolicy(Qt::CustomContextMenu); connect(table,&QWidget::customContextMenuRequested,this,[this,table](const QPoint& point) {
            const auto index=table->indexAt(point); if(!index.isValid()) return; table->selectRow(index.row()); const auto copiedValue=table->item(index.row(),index.column())->text(); const auto copiedRow=tableRowText(table,index.row()); QMenu menu; auto* value=menu.addAction("Copy value"); auto* row=menu.addAction("Copy row"); const auto selected=menu.exec(table->viewport()->mapToGlobal(point)); if(ending || !unlocked) return; if(selected==value) copySessionText(copiedValue); else if(selected==row) copySessionText(copiedRow);
        });
    }

    void copyPublicKey(const QString& fingerprint,std::function<void()> after = {}) {
        if(pending || !unlocked) return;
        request("public_export",{{"fingerprint",fingerprint}},[this,after](bool ok,const QJsonObject& data) {if(ok) {copySessionText(data.value("text").toString()); statusBar()->showMessage("Public key copied. Public exports reveal its identities."); if(after) after();}});
    }

    void exportKey(const QString& operation,const QString& fingerprint) {
        if(pending || !unlocked) return;
        performCrypto(operation,{{"fingerprint",fingerprint}},[this,operation](bool ok,const QJsonObject& data) {if(ok) {outputIsEncrypted=false; clearVerificationIdentity(); output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1); showNotepad(); statusBar()->showMessage(operation=="revocation_export"?"Revocation certificate: back up privately; publish only when revoking.":data.value("protected").toBool()?"Private export retains its key-password protection.":"Private export contains unprotected secret packets. Keep it private.");}});
    }

    void confirmPrivateExport(const QString& fingerprint) {
        const auto key=keyRecord(fingerprint); if(!key.value("has_secret").toBool()) return;
        const auto text=key.value("secret_protected").toBool()?QString("Display the password-protected private key for backup? Copying it puts it outside the vault."):QString("This key contains unprotected secret packets. Anyone who obtains them can use them. Display them for backup?");
        if(QMessageBox::question(this,"Export private key",text,QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)==QMessageBox::Yes) exportKey("private_export",fingerprint);
    }

    void installKeyMenu(QTableWidget* table,bool actions=true) {
        table->setContextMenuPolicy(Qt::CustomContextMenu); connect(table,&QWidget::customContextMenuRequested,this,[this,table,actions](const QPoint& point) {
            const auto index=table->indexAt(point); if(!index.isValid()) return; table->selectRow(index.row()); const auto fp=table->item(index.row(),2)->text(); const auto key=keyRecord(fp); const auto copiedValue=table->item(index.row(),index.column())->text(); const auto copiedRow=tableRowText(table,index.row());
            QMenu menu; auto* value=menu.addAction("Copy value"); auto* fingerprint=menu.addAction("Copy fingerprint"); auto* row=menu.addAction("Copy row"); auto* publicKey=actions?menu.addAction("Copy public key"):nullptr; if(publicKey) publicKey->setEnabled(!pending);
            QAction *makeDefault=nullptr,*clearDefault=nullptr,*subkeys=nullptr,*password=nullptr,*privateKey=nullptr,*revocation=nullptr;
            if(actions) {
                menu.addSeparator(); makeDefault=menu.addAction("Use as default signing key"); makeDefault->setEnabled(!pending && !sessionReadOnly && key.value("can_sign").toBool());
                clearDefault=menu.addAction("Clear default signing key"); clearDefault->setEnabled(!pending && !sessionReadOnly && defaultSigner==fp);
                subkeys=menu.addAction("View / manage subkeys…"); subkeys->setEnabled(!pending);
                password=menu.addAction("Edit key password…"); password->setEnabled(!pending && !sessionReadOnly && key.value("has_secret").toBool());
                privateKey=menu.addAction("Show private key…"); privateKey->setEnabled(!pending && key.value("has_secret").toBool());
                revocation=menu.addAction("Show revocation certificate…"); revocation->setEnabled(!pending && key.value("has_secret").toBool());
            }
            const auto selected=menu.exec(table->viewport()->mapToGlobal(point)); if(!selected || ending || !unlocked) return;
            if(selected==value) copySessionText(copiedValue); else if(selected==fingerprint) copySessionText(fp); else if(selected==row) copySessionText(copiedRow);
            else if(!pending && selected==publicKey) copyPublicKey(fp); else if(!pending && selected==makeDefault) saveDefaultKey(fp); else if(!pending && selected==clearDefault) saveDefaultKey({}); else if(!pending && selected==subkeys) subkeysDialog(fp); else if(!pending && selected==password) protectKeyDialog(fp); else if(!pending && selected==privateKey) confirmPrivateExport(fp);
            else if(!pending && selected==revocation && QMessageBox::question(this,"Revocation certificate","Anyone with this certificate can revoke your key. Keep it private until revoking.",QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)==QMessageBox::Yes) exportKey("revocation_export",fp);
        });
    }

    static void styleTable(QTableWidget* table) {
        table->setSelectionBehavior(QAbstractItemView::SelectRows); table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers); table->setAlternatingRowColors(true); table->setShowGrid(false);
        table->verticalHeader()->hide(); table->verticalHeader()->setDefaultSectionSize(32);
        table->horizontalHeader()->setHighlightSections(false); table->horizontalHeader()->setMinimumSectionSize(65);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive); table->horizontalHeader()->setSectionsMovable(true); table->horizontalHeader()->setStretchLastSection(false); table->setSortingEnabled(true);
        table->setStyleSheet("QTableWidget { border: 1px solid palette(mid); border-radius: 4px; } QTableWidget::item { padding: 4px 6px; border-bottom: 1px solid palette(midlight); } QHeaderView::section { padding: 6px; font-weight: 600; border: none; border-bottom: 1px solid palette(mid); }");
    }

    QString keyIdentity(const QJsonObject& key) const {
        QStringList identities; for(const auto& value:key.value("identities").toArray()) identities.append(value.toString());
        return identities.isEmpty()?QString("No valid identity"):identities.join("; ");
    }

    QString keyDescription(const QString& fingerprint) const {
        for(const auto& value:cachedKeys) {const auto key=value.toObject(); if(key.value("fingerprint").toString()==fingerprint) return keyIdentity(key)+" — "+fingerprint;}
        return fingerprint;
    }

    QString profileTitle(const QString& id) const {
        if(id.isEmpty()) return "All";
        for(const auto& value:profiles) if(value.toObject().value("id").toString()==id) return value.toObject().value("name").toString();
        return "Unknown profile";
    }

    bool profileAllows(const QString& fingerprint) const {
        if(activeProfile.isEmpty()) return true;
        for(const auto& value:profiles) {
            const auto profile=value.toObject(); if(profile.value("id").toString()!=activeProfile) continue;
            for(const auto& member:profile.value("fingerprints").toArray()) if(member.toString()==fingerprint) return true;
        }
        return false;
    }

    int profileTabIndex(const QString& id) const {
        for(int i=0;i<profileTabs->count()-1;++i) if(profileTabs->tabData(i).toString()==id) return i;
        return 0;
    }

    void rebuildProfileTabs() {
        QSignalBlocker block(profileTabs);
        while(profileTabs->count()) profileTabs->removeTab(0);
        profileTabs->addTab("All"); profileTabs->setTabData(0,QString());
        bool exists=activeProfile.isEmpty();
        for(const auto& value:profiles) {const auto profile=value.toObject(); const int i=profileTabs->addTab(profile.value("name").toString()); const auto id=profile.value("id").toString(); profileTabs->setTabData(i,id); if(id==activeProfile) exists=true;}
        if(!exists) activeProfile.clear();
        const int plus=profileTabs->addTab("+"); profileTabs->setTabToolTip(plus,"Create an identity"); profileTabs->setTabEnabled(plus,!sessionReadOnly); profileTabs->setCurrentIndex(profileTabIndex(activeProfile));
        syncNotepadProfiles();
    }

    void selectProfile(const QString& id) {
        if(id!=activeProfile) {activeProfile=id; currentDocumentId.clear(); currentDocumentTitle.clear(); updateDocumentContext(); if(documents) documents->setRowCount(0);}
        {QSignalBlocker block(profileTabs); profileTabs->setCurrentIndex(profileTabIndex(activeProfile));}
        syncNotepadProfiles(); renderKeys();
        if(unlocked && !pending && (tabs->currentIndex()==1 || tabs->currentIndex()==3 || (notepadWindow && notepadWindow->isVisible()))) refreshDocuments();
        statusBar()->showMessage("Profile: "+profileTitle(activeProfile)+". Profiles organize this vault; they do not add separate encryption.");
    }

    void refreshKeys(std::function<void()> after = {}) {
        request("list",{},[this,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            cachedKeys=data.value("keys").toArray(); profiles=data.value("profiles").toArray(); profileDocumentCounts=data.value("profile_document_counts").toObject(); defaultSigner=data.value("default_signing_key").toString();
            rebuildProfileTabs(); renderKeys(); populateProfileManager(); applyReadOnlyUi(); updateSessionStats(); if(workflowEditor) workflowEditor->setKeys(cachedKeys);
            if(after) after();
        });
    }

    static void configureKeyTable(QTableWidget* table,const QString& first) {
        table->setHorizontalHeaderLabels({first,"Identity","Fingerprint","Key material","Status","Algorithm","Created","Expires","Capabilities"}); styleTable(table);
        const QList<int> widths{74,190,300,142,110,95,98,98,170}; for(int i=0;i<widths.size();++i) table->setColumnWidth(i,widths[i]);
        table->sortItems(1,Qt::AscendingOrder);
    }

    void appendKeyRow(QTableWidget* table,const QJsonObject& key,const QString& first,bool checkable=false,bool checked=false,bool pinned=false) {
        const int row=table->rowCount(); table->insertRow(row); const auto fp=key.value("fingerprint").toString();
        QStringList capabilities; for(const auto& value:key.value("capabilities").toArray()) capabilities.append(value.toString());
        const auto created=key.value("created_at"), expires=key.value("expires_at");
        const auto formatDate=[](const QJsonValue& value,const QString& empty) {return value.isDouble()?QDateTime::fromSecsSinceEpoch(value.toInteger()).toLocalTime().toString("yyyy-MM-dd"):empty;};
        QStringList fields{first,keyIdentity(key),fp,key.value("has_secret").toBool()?(key.value("secret_protected").toBool()?"Private · password":key.value("secret_any_protected").toBool()?"Private · mixed":"Private · no password"):"Public only",key.value("status").toString(),key.value("algorithm").toString(),formatDate(created,"Unknown"),formatDate(expires,"Never"),capabilities.join(", ")};
        for(int column=0;column<fields.size();++column) {
            auto* item=new TableItem(fields[column]); item->setToolTip(fields[column]); item->setData(Qt::UserRole,fp); if(pinned) item->setData(Qt::UserRole+21,checked);
            if(column==6 || column==7) {const auto date=column==6?created:expires; item->setData(Qt::UserRole+20,date.isDouble()?date.toInteger():std::numeric_limits<qint64>::max());}
            if(column==0 && checkable) {item->setFlags(item->flags()|Qt::ItemIsUserCheckable); item->setCheckState(checked?Qt::Checked:Qt::Unchecked);}
            table->setItem(row,column,item);
        }
        auto* fingerprint=table->item(row,2); fingerprint->setData(Qt::UserRole+1,key.value("can_sign").toBool()); fingerprint->setData(Qt::UserRole+3,key.value("secret_protected").toBool()); fingerprint->setData(Qt::UserRole+4,key.value("has_revocation").toBool()); fingerprint->setData(Qt::UserRole+5,key.value("has_secret").toBool());
        fingerprint->setData(Qt::UserRole+2,key.value("algorithm").toString()+" · Created: "+fields[6]+" · Expires: "+fields[7]+"\nCapabilities: "+capabilities.join("; "));
    }

    static void filterKeyTable(QTableWidget* table,const QString& term,int status) {
        for(int row=0;row<table->rowCount();++row) {
            bool matches=false; for(int column=1;column<table->columnCount();++column) matches=matches||table->item(row,column)->text().contains(term,Qt::CaseInsensitive);
            const auto state=table->item(row,4)->text(); const bool secret=table->item(row,2)->data(Qt::UserRole+5).toBool();
            const bool allowed=status==0 || (status==1 && state=="Valid") || (status==2 && state.contains("expired",Qt::CaseInsensitive)) || (status==3 && state.contains("revoked",Qt::CaseInsensitive)) || (status==4 && secret) || (status==5 && !secret);
            table->setRowHidden(row,!matches || !allowed);
        }
    }

    void renderKeys() {
        QStringList chosenRecipients;
        for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) chosenRecipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
        const auto previousSigner=signingChoice->currentData().toString();
        QSignalBlocker signingBlock(signingChoice), recipientsBlock(recipientChoices), keysBlock(keys);
        const auto selectedKey=keys->currentRow()<0?QString():keys->item(keys->currentRow(),2)->text();
        keys->setSortingEnabled(false); recipientChoices->setSortingEnabled(false);
        keys->setRowCount(0); details->setText("Select a key to inspect its full fingerprint."); recipientChoices->clear(); signingChoice->clear(); signingChoice->addItem("Select a signing key",QString());
        for(const auto& entry:cachedKeys) {
            const auto key=entry.toObject(); const auto fp=key.value("fingerprint").toString(); if(!profileAllows(fp)) continue;
            appendKeyRow(keys,key,fp==defaultSigner?"Default":"");
            appendKeyRow(recipientChoices,key,key.value("can_encrypt").toBool()?QString():QString("Unavailable"),key.value("can_encrypt").toBool(),key.value("can_encrypt").toBool() && chosenRecipients.contains(fp));
            if(key.value("can_sign").toBool()) {signingChoice->addItem(keyIdentity(key)+" · "+fp.right(16),fp); signingChoice->setItemData(signingChoice->count()-1,fp+(key.value("signing_password_required").toBool()?"\nPassword required to sign":"\nSigning key available without a password"),Qt::ToolTipRole);}
        }
        keys->setSortingEnabled(true); recipientChoices->setSortingEnabled(true);
        for(int row=0;row<keys->rowCount();++row) if(keys->item(row,2)->text()==selectedKey) {keys->selectRow(row); break;}
        const auto wanted=previousSigner.isEmpty()?defaultSigner:previousSigner;
        signingChoice->setCurrentIndex(qMax(0,signingChoice->findData(wanted))); updateSelection();
        filterKeyTable(keys,search->text(),keyStatus->currentIndex());
    }

    void buildIdentities() {
        auto* page=new QWidget; auto* layout=new QVBoxLayout(page);
        auto* title=new QLabel("Identities and profiles"); title->setStyleSheet("font-size: 20px; font-weight: 600;"); layout->addWidget(title);
        auto* hint=new QLabel("Select an identity on the left to edit its private details and associated keys. KDBX stores identities as KeePass groups. These details do not change public OpenPGP identities."); hint->setWordWrap(true); layout->addWidget(hint);
        profileSelector=new QComboBox(page); profileSelector->hide();
        auto* sections=new QSplitter(Qt::Vertical); auto* overview=new QSplitter;
        auto* listPanel=new QWidget; auto* listLayout=new QVBoxLayout(listPanel); listLayout->setContentsMargins(0,0,7,0);
        identityOverview=new QTableWidget(0,3); identityOverview->setHorizontalHeaderLabels({"Identity","Keys","Documents"}); styleTable(identityOverview); identityOverview->setColumnWidth(0,190); identityOverview->setColumnWidth(1,68); identityOverview->setColumnWidth(2,90); listLayout->addWidget(identityOverview,1);
        auto* add=new QPushButton("New identity…"); listLayout->addWidget(add); overview->addWidget(listPanel);
        auto* properties=new QWidget; auto* form=new QFormLayout(properties);
        profileName=new QLineEdit; profileName->setMaxLength(80); profileUsername=new QLineEdit; profileUsername->setMaxLength(256); profileEmail=new QLineEdit; profileEmail->setMaxLength(256); profileUrl=new QLineEdit; profileUrl->setMaxLength(2048); profileNotes=editor("Private identity notes…"); profileNotes->setMaximumHeight(85);
        form->addRow("Name",profileName); form->addRow("Username / pseudonym",profileUsername); form->addRow("Email",profileEmail); form->addRow("Website",profileUrl); form->addRow("Notes",profileNotes); overview->addWidget(properties); overview->setStretchFactor(0,1); overview->setStretchFactor(1,1); overview->setSizes({400,500}); sections->addWidget(overview);
        auto* membership=new QWidget; auto* memberLayout=new QVBoxLayout(membership); memberLayout->setContentsMargins(0,0,0,0);
        auto* filters=new QHBoxLayout; identitySearch=new QLineEdit; identitySearch->setPlaceholderText("Filter key name, fingerprint, dates or other fields…"); filters->addWidget(identitySearch,1); identityStatus=new QComboBox; identityStatus->addItems({"All keys","Usable","Expired","Revoked","Private keys","Public only"}); filters->addWidget(identityStatus); memberLayout->addLayout(filters);
        auto* memberHint=new QLabel("Checked keys belong to this identity and stay at the top. Click a column heading to sort within each group."); memberHint->setWordWrap(true); memberLayout->addWidget(memberHint);
        profileMembers=new CheckedKeyTable; configureKeyTable(profileMembers,"Included"); profileMembers->setMinimumHeight(160); memberLayout->addWidget(profileMembers,1); sections->addWidget(membership); sections->setChildrenCollapsible(false); sections->setStretchFactor(1,1); sections->setSizes({270,310}); layout->addWidget(sections,1);
        auto* actions=new QHBoxLayout; profileSaveButton=new QPushButton("Save identity"); profileDeleteButton=new QPushButton("Delete identity…"); actions->addWidget(profileSaveButton); actions->addWidget(profileDeleteButton); actions->addStretch(); layout->addLayout(actions);
        connect(add,&QPushButton::clicked,this,[this] {createProfileDialog();});
        for(auto* field:{profileName,profileUsername,profileEmail,profileUrl}) connect(field,&QLineEdit::textChanged,this,[this] {if(!loadingIdentity) identityDirty=true;});
        connect(profileNotes,&QPlainTextEdit::textChanged,this,[this] {if(!loadingIdentity) identityDirty=true;});
        connect(identityOverview,&QTableWidget::itemSelectionChanged,this,[this] {const int row=identityOverview->currentRow(); if(row>=0) profileSelector->setCurrentIndex(qMax(0,profileSelector->findData(identityOverview->item(row,0)->data(Qt::UserRole))));});
        connect(profileSelector,&QComboBox::currentIndexChanged,this,[this] {populateProfileMembers(); selectIdentityOverview(profileSelector->currentData().toString());});
        auto filter=[this] {filterKeyTable(profileMembers,identitySearch->text(),identityStatus->currentIndex());};
        connect(identitySearch,&QLineEdit::textChanged,this,filter); connect(identityStatus,&QComboBox::currentIndexChanged,this,filter);
        connect(profileMembers->horizontalHeader(),&QHeaderView::sortIndicatorChanged,this,[this,filter] {QTimer::singleShot(0,this,filter);});
        connect(profileMembers,&QTableWidget::itemChanged,this,[this](QTableWidgetItem* changed) {
            if(changed->column()!=0) return;
            if(!loadingIdentity) identityDirty=true;
            {QSignalBlocker block(profileMembers); for(int column=0;column<profileMembers->columnCount();++column) profileMembers->QTableWidget::item(changed->row(),column)->setData(Qt::UserRole+21,changed->checkState()==Qt::Checked);}
            profileMembers->sortItems(profileMembers->horizontalHeader()->sortIndicatorSection(),profileMembers->horizontalHeader()->sortIndicatorOrder()); filterKeyTable(profileMembers,identitySearch->text(),identityStatus->currentIndex());
        });
        connect(profileSaveButton,&QPushButton::clicked,this,[this] {
            const auto id=profileSelector->currentData().toString(); if(id.isEmpty()) return;
            QJsonArray members; for(int i=0;i<profileMembers->count();++i) if(profileMembers->item(i)->checkState()==Qt::Checked) members.append(profileMembers->item(i)->data(Qt::UserRole).toString());
            request("profile_save",{{"profile_id",id},{"profile_name",profileName->text()},{"profile_username",profileUsername->text()},{"profile_email",profileEmail->text()},{"profile_url",profileUrl->text()},{"profile_notes",profileNotes->toPlainText()},{"profile_fingerprints",members}},[this](bool ok,const QJsonObject&) {if(ok) {identityDirty=false; refreshKeys([this] {statusBar()->showMessage("Identity and key assignments saved inside this vault.");});}});
        });
        connect(profileDeleteButton,&QPushButton::clicked,this,[this] {
            const auto id=profileSelector->currentData().toString(); if(id.isEmpty()) return;
            if(QMessageBox::question(this,"Delete identity","Delete this identity? Its keys and documents are kept; documents become unassigned.",QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes) return;
            request("profile_delete",{{"profile_id",id}},[this](bool ok,const QJsonObject&) {if(ok) {identityDirty=false; refreshKeys();}});
        });
        identityOverview->setContextMenuPolicy(Qt::CustomContextMenu); connect(identityOverview,&QWidget::customContextMenuRequested,this,[this](const QPoint& point) {const auto index=identityOverview->indexAt(point); if(!index.isValid()) return; identityOverview->selectRow(index.row()); const auto value=identityOverview->item(index.row(),index.column())->text(); const auto id=identityOverview->item(index.row(),0)->data(Qt::UserRole).toString(); QMenu menu; auto* copy=menu.addAction("Copy value"); auto* edit=menu.addAction("Edit identity"); const auto selected=menu.exec(identityOverview->viewport()->mapToGlobal(point)); if(ending || !unlocked) return; if(selected==copy) copySessionText(value); else if(selected==edit) {profileSelector->setCurrentIndex(qMax(0,profileSelector->findData(id))); if(editedIdentityId==id) profileName->setFocus();}});
        installKeyMenu(profileMembers); vaultMutationControls.append(page); tabs->addTab(page,"Identities");
    }

    void selectIdentityOverview(const QString& id) {
        if(!identityOverview) {return;} QSignalBlocker block(identityOverview);
        for(int row=0;row<identityOverview->rowCount();++row) if(identityOverview->item(row,0)->data(Qt::UserRole).toString()==id) {identityOverview->selectRow(row); return;}
        identityOverview->clearSelection(); identityOverview->setCurrentItem(nullptr);
    }

    void refreshIdentityCounts() {
        if(!identityOverview) {return;} QSignalBlocker block(identityOverview); const bool sorting=identityOverview->isSortingEnabled(); identityOverview->setSortingEnabled(false);
        for(int row=0;row<identityOverview->rowCount();++row) {const auto id=identityOverview->item(row,0)->data(Qt::UserRole).toString(); const auto count=profileDocumentCounts.value(id).toInteger(); identityOverview->item(row,2)->setText(QString::number(count)); identityOverview->item(row,2)->setData(Qt::UserRole+20,count);}
        identityOverview->setSortingEnabled(sorting);
    }

    void populateProfileManager() {
        if(!profileSelector || !identityOverview) return;
        const auto previous=profileSelector->currentData().toString();
        QSignalBlocker block(profileSelector), overviewBlock(identityOverview); profileSelector->clear(); profileSelector->addItem("Choose an identity",QString()); identityOverview->setSortingEnabled(false); identityOverview->setRowCount(0);
        for(const auto& value:profiles) {const auto profile=value.toObject(); const auto id=profile.value("id").toString(); profileSelector->addItem(profile.value("name").toString(),id);
            const int row=identityOverview->rowCount(); identityOverview->insertRow(row); auto* name=new TableItem(profile.value("name").toString()); name->setData(Qt::UserRole,id); identityOverview->setItem(row,0,name);
            auto* keys=new TableItem(QString::number(profile.value("fingerprints").toArray().size())); keys->setData(Qt::UserRole+20,profile.value("fingerprints").toArray().size()); identityOverview->setItem(row,1,keys); identityOverview->setItem(row,2,new TableItem("0"));
        }
        identityOverview->setSortingEnabled(true); refreshIdentityCounts();
        const auto wanted=previous.isEmpty()?activeProfile:previous; profileSelector->setCurrentIndex(qMax(0,profileSelector->findData(wanted))); populateProfileMembers(); selectIdentityOverview(profileSelector->currentData().toString());
    }

    void populateProfileMembers() {
        if(!profileMembers) return;
        const auto id=profileSelector->currentData().toString();
        if(identityDirty && id!=editedIdentityId && !editedIdentityId.isEmpty() && !testing && QMessageBox::question(this,"Unsaved identity changes","Discard this identity's unsaved changes and select another?",QMessageBox::Discard|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Discard) {QSignalBlocker block(profileSelector); profileSelector->setCurrentIndex(qMax(0,profileSelector->findData(editedIdentityId))); selectIdentityOverview(editedIdentityId); return;}
        const bool preserve=identityDirty && id==editedIdentityId; QJsonObject selected; QJsonArray members;
        for(const auto& value:profiles) if(value.toObject().value("id").toString()==id) selected=value.toObject();
        QSet<QString> incoming; for(const auto& value:selected.value("fingerprints").toArray()) incoming.insert(value.toString());
        auto effective=incoming;
        if(preserve) {for(int row=0;row<profileMembers->count();++row) {const auto fp=profileMembers->item(row)->data(Qt::UserRole).toString(); const bool checked=profileMembers->item(row)->checkState()==Qt::Checked; if(checked!=identityBaselineMembers.contains(fp)) {if(checked) effective.insert(fp); else effective.remove(fp);}}}
        identityBaselineMembers=incoming; for(const auto& fp:effective) members.append(fp);
        loadingIdentity=true;
        if(!preserve) { profileName->setText(selected.value("name").toString()); profileUsername->setText(selected.value("username").toString()); profileEmail->setText(selected.value("email").toString()); profileUrl->setText(selected.value("url").toString()); profileNotes->setPlainText(selected.value("notes").toString()); identityDirty=false;}
        editedIdentityId=id;
        for(auto* field:{profileName,profileUsername,profileEmail,profileUrl}) {field->setEnabled(!id.isEmpty());}
        profileNotes->setEnabled(!id.isEmpty()); profileMembers->setEnabled(!id.isEmpty()); profileSaveButton->setEnabled(!id.isEmpty()); profileDeleteButton->setEnabled(!id.isEmpty());
        {QSignalBlocker block(profileMembers); profileMembers->setSortingEnabled(false); profileMembers->clear();
        for(const auto& value:cachedKeys) {const auto key=value.toObject(); bool checked=false; for(const auto& member:members) checked=checked||member.toString()==key.value("fingerprint").toString(); appendKeyRow(profileMembers,key,QString(),true,checked,true);}
        profileMembers->setSortingEnabled(true); filterKeyTable(profileMembers,identitySearch->text(),identityStatus->currentIndex());}
        loadingIdentity=false;
    }

    void createProfileDialog() {
        if(!unlocked || pending || sessionReadOnly) return;
        QDialog dialog(this); dialog.setWindowTitle("Create identity"); dialog.resize(820,650); auto* layout=new QVBoxLayout(&dialog);
        auto* hint=new QLabel("Create private identity details, then optionally include available keys below. Keys can belong to more than one identity."); hint->setWordWrap(true); layout->addWidget(hint); auto* form=new QFormLayout;
        auto* name=new QLineEdit; name->setMaxLength(80); name->setPlaceholderText("Identity, project or category"); auto* username=new QLineEdit; username->setMaxLength(256); auto* email=new QLineEdit; email->setMaxLength(256); auto* url=new QLineEdit; url->setMaxLength(2048); auto* notes=editor("Private notes…"); notes->setMaximumHeight(75);
        form->addRow("Name",name); form->addRow("Username / pseudonym",username); form->addRow("Email (optional)",email); form->addRow("Website (optional)",url); form->addRow("Notes (optional)",notes); layout->addLayout(form);
        auto* filter=new QLineEdit; filter->setPlaceholderText("Find available keys to include…"); layout->addWidget(filter); auto* available=new CheckedKeyTable; configureKeyTable(available,"Include"); available->setSortingEnabled(false); available->setMinimumHeight(150);
        for(const auto& value:cachedKeys) {appendKeyRow(available,value.toObject(),QString(),true,false);} available->setSortingEnabled(true); layout->addWidget(available,1); installKeyMenu(available,false);
        connect(filter,&QLineEdit::textChanged,&dialog,[available](const QString& term) {filterKeyTable(available,term,0);});
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); buttons->button(QDialogButtonBox::Save)->setText("Create identity"); buttons->button(QDialogButtonBox::Save)->setEnabled(false); layout->addWidget(buttons); connect(name,&QLineEdit::textChanged,&dialog,[=] {buttons->button(QDialogButtonBox::Save)->setEnabled(!name->text().trimmed().isEmpty());}); connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        if(dialog.exec()!=QDialog::Accepted) return;
        QJsonArray members; for(int row=0;row<available->count();++row) if(available->item(row)->checkState()==Qt::Checked) members.append(available->item(row)->data(Qt::UserRole).toString());
        request("profile_save",{{"profile_name",name->text()},{"profile_username",username->text()},{"profile_email",email->text()},{"profile_url",url->text()},{"profile_notes",notes->toPlainText()},{"profile_fingerprints",members}},[this](bool ok,const QJsonObject& data) {if(ok) {activeProfile=data.value("id").toString(); refreshKeys([this] {profileSelector->setCurrentIndex(qMax(0,profileSelector->findData(activeProfile))); selectIdentityOverview(profileSelector->currentData().toString()); tabs->setCurrentIndex(2); show(); raise(); profileName->setFocus();});}});
    }

    void syncNotepadProfiles() {
        if(!notepadProfileTabs) return;
        QSignalBlocker block(notepadProfileTabs); while(notepadProfileTabs->count()) notepadProfileTabs->removeTab(0);
        for(int i=0;i<profileTabs->count();++i) {const auto index=notepadProfileTabs->addTab(profileTabs->tabText(i)); notepadProfileTabs->setTabData(index,profileTabs->tabData(i)); notepadProfileTabs->setTabEnabled(index,profileTabs->isTabEnabled(i));}
        notepadProfileTabs->setCurrentIndex(profileTabIndex(activeProfile));
    }

    void configureNotepad() {
        if(!notepadPage || !notepadHost) return;
        if(notepadPopout) {
            if(!notepadWindow) {
                notepadWindow=new QDialog(this,Qt::Window); notepadWindow->setObjectName("notepadWindow"); notepadWindow->setWindowTitle("PGPCrypt — Notepad"); notepadWindow->resize(1160,820); notepadWindow->setModal(false); notepadWindow->installEventFilter(this);
                auto* layout=new QVBoxLayout(notepadWindow); auto* header=new QHBoxLayout; auto* title=new QLabel("Notepad"); title->setStyleSheet("font-size: 19px; font-weight: 600;"); header->addWidget(title); header->addStretch();
                auto* lock=new QPushButton("Lock vault  Ctrl+L"); header->addWidget(lock); connect(lock,&QPushButton::clicked,this,[this] {endSession(true);}); layout->addLayout(header);
                auto* shortcut=new QAction(notepadWindow); shortcut->setShortcut(QKeySequence("Ctrl+L")); notepadWindow->addAction(shortcut); connect(shortcut,&QAction::triggered,this,[this] {endSession(true);});
                notepadProfileTabs=new QTabBar; notepadProfileTabs->setExpanding(false); notepadProfileTabs->setUsesScrollButtons(true); layout->addWidget(notepadProfileTabs);
                connect(notepadProfileTabs,&QTabBar::currentChanged,this,[this](int index) {
                    if(index<0 || pending || ending) {syncNotepadProfiles(); return;}
                    if(index==notepadProfileTabs->count()-1) {syncNotepadProfiles(); if(!sessionReadOnly) createProfileDialog(); return;}
                    selectProfile(notepadProfileTabs->tabData(index).toString());
                });
                connect(notepadWindow,&QDialog::finished,this,[this] {if(!ending && tabs->currentIndex()==1) tabs->setCurrentIndex(0);});
            }
            if(notepadPage->parentWidget()!=notepadWindow) {notepadPage->setParent(notepadWindow); notepadWindow->layout()->addWidget(notepadPage); notepadPage->show();}
            notepadPlaceholder->show(); syncNotepadProfiles();
            if(unlocked && tabs->currentIndex()==1) showNotepad();
        } else {
            if(notepadWindow) {notepadWindow->hide();} notepadPlaceholder->hide();
            if(notepadPage->parentWidget()!=notepadHost) {notepadPage->setParent(notepadHost); notepadHostLayout->addWidget(notepadPage); notepadPage->show();}
        }
    }

    void showNotepad() {
        if(notepadPopout && notepadWindow && unlocked && !ending) {notepadWindow->show(); notepadWindow->raise(); if(!testing) notepadWindow->activateWindow();}
    }

    void buildText() {
        auto* page=new QWidget; notepadPage=page; auto* layout=new QVBoxLayout(page); layout->setSpacing(7);
        auto* sectionSplitter=new QSplitter(Qt::Vertical); sectionSplitter->setChildrenCollapsible(false); auto* selectorPanel=new QWidget; auto* selectorLayout=new QVBoxLayout(selectorPanel); selectorLayout->setContentsMargins(0,0,0,0);
        auto* recipientLabel=new QLabel("Encryption recipients — check one or more keys"); selectorLayout->addWidget(recipientLabel);
        recipientChoices=new CheckedKeyTable; configureKeyTable(recipientChoices,"Encrypt to"); installKeyMenu(recipientChoices); recipientChoices->setMinimumHeight(150); selectorLayout->addWidget(recipientChoices,1);
        auto* form=new QFormLayout; form->setVerticalSpacing(6);
        signingChoice=new QComboBox; signingChoice->setMinimumContentsLength(24); signingChoice->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon); signingChoice->addItem("Select a signing key",QString()); form->addRow("Signing key",signingChoice); selectorLayout->addLayout(form);
        auto* defaults=new QHBoxLayout; auto* setDefault=new QPushButton("Use as default"); defaults->addWidget(setDefault); auto* clearDefault=new QPushButton("Clear default"); defaults->addWidget(clearDefault);
        defaultKeyLabel=new QLabel; defaultKeyLabel->setTextFormat(Qt::PlainText); defaultKeyLabel->setWordWrap(true); defaults->addWidget(defaultKeyLabel,1); selectorLayout->addLayout(defaults);
        connect(setDefault,&QPushButton::clicked,this,[this] {const auto fp=signingChoice->currentData().toString(); if(fp.isEmpty()) {fail("Choose a signing key on the notepad"); return;} saveDefaultKey(fp);});
        connect(clearDefault,&QPushButton::clicked,this,[this] {saveDefaultKey({});}); vaultMutationControls.append(setDefault); vaultMutationControls.append(clearDefault);
        connect(signingChoice,&QComboBox::currentIndexChanged,this,[this] {updateSelection();}); connect(recipientChoices,&QTableWidget::itemChanged,this,[this] {updateSelection();});
        selectionSummary=new QLabel; selectionSummary->setTextFormat(Qt::PlainText); selectionSummary->setWordWrap(true); selectorLayout->addWidget(selectionSummary); sectionSplitter->addWidget(selectorPanel);
        auto* workspace=new QSplitter;
        auto* browser=new QWidget; auto* browserLayout=new QVBoxLayout(browser); browserLayout->setContentsMargins(0,0,7,0); browser->setMinimumWidth(190); browser->setMaximumWidth(320);
        auto* browserTitle=new QLabel("Recent saved notes"); browserTitle->setStyleSheet("font-weight: 600;"); browserLayout->addWidget(browserTitle);
        recentDocuments=new QTableWidget(0,2); recentDocuments->setHorizontalHeaderLabels({"Document","Modified"}); styleTable(recentDocuments); recentDocuments->setColumnWidth(0,150); recentDocuments->setColumnWidth(1,130); recentDocuments->setSortingEnabled(false); recentDocuments->horizontalHeader()->setSectionsClickable(false); browserLayout->addWidget(recentDocuments,1);
        auto loadRecent=[this] {const auto row=recentDocuments->currentRow(); if(row>=0) openVaultDocument(recentDocuments->item(row,0)->data(Qt::UserRole).toString());};
        auto* load=new QPushButton("Load selected"); browserLayout->addWidget(load); connect(load,&QPushButton::clicked,this,loadRecent); connect(recentDocuments,&QTableWidget::cellDoubleClicked,this,[loadRecent](int,int) {loadRecent();});
        auto* manage=new QPushButton("Manage saved notes…"); browserLayout->addWidget(manage); connect(manage,&QPushButton::clicked,this,[this] {tabs->setCurrentIndex(3); if(notepadWindow) notepadWindow->hide();}); workspace->addWidget(browser);
        auto* textWorkspace=new QWidget; auto* textLayout=new QVBoxLayout(textWorkspace); textLayout->setContentsMargins(0,0,0,0); textLayout->setSpacing(6);
        documentContext=new QLabel("Unsaved text — stored only when you choose Save in vault."); documentContext->setTextFormat(Qt::PlainText); documentContext->setWordWrap(true); textLayout->addWidget(documentContext);
        input=editor("Paste text or import a message. Nothing is saved automatically…"); output=editor("Result appears here after the operation succeeds…",true);
        auto* inputPanel=new QWidget; auto* inputLayout=new QVBoxLayout(inputPanel); inputLayout->setContentsMargins(0,0,0,0); inputLayout->setSpacing(4);
        auto* inputHeading=new QHBoxLayout; inputHeading->addWidget(new QLabel("Input"));inputHeading->addStretch();pasteInput=new QPushButton("Paste");pasteInput->setToolTip("Replace all Input with clipboard text.");inputHeading->addWidget(pasteInput);inputLayout->addLayout(inputHeading);connect(pasteInput,&QPushButton::clicked,this,[this]{input->setPlainText(qApp->clipboard()->text());});
        auto* outputPanel=new QWidget;auto* outputLayout=new QVBoxLayout(outputPanel);outputLayout->setContentsMargins(0,0,0,0);outputLayout->setSpacing(4);auto* outputHeading=new QHBoxLayout;outputHeading->addWidget(new QLabel("Output"));outputHeading->addStretch();copyOutput=new QPushButton("Copy all");outputHeading->addWidget(copyOutput);outputLayout->addLayout(outputHeading);
        for(int source=0;source<2;++source){auto* actions=new QHBoxLayout;for(const auto& op:QStringList{"sign","verify","encrypt","decrypt"}) {auto* button=new QPushButton(op[0].toUpper()+op.mid(1));button->setObjectName(op+(source?"Output":"Input"));actions->addWidget(button);connect(button,&QPushButton::clicked,this,[this,op,source]{textAction(op,{},source==1);});if(source){button->setEnabled(false);outputActions.append(button);}}(source?outputLayout:inputLayout)->addLayout(actions);}
        inputLayout->addWidget(input,1);verificationIdentity=new QLabel;verificationIdentity->setTextFormat(Qt::PlainText);verificationIdentity->setWordWrap(true);verificationIdentity->setTextInteractionFlags(Qt::TextSelectableByMouse);verificationIdentity->hide();outputLayout->addWidget(verificationIdentity);outputLayout->addWidget(output,1);
        connect(output,&QPlainTextEdit::textChanged,this,[this]{outputProof={};outputProofDigest.clear();for(auto* button:outputActions)button->setEnabled(!output->toPlainText().isEmpty());copyOutput->setEnabled(!output->toPlainText().isEmpty());});copyOutput->setEnabled(false);connect(copyOutput,&QPushButton::clicked,this,[this]{copySessionText(output->toPlainText());statusBar()->showMessage("Output copied. Clipboard managers may retain it.");});
        auto* panes=new QSplitter(Qt::Horizontal);panes->setObjectName("notepadPanes");panes->addWidget(inputPanel);panes->addWidget(outputPanel);panes->setChildrenCollapsible(false);panes->setSizes({450,450});textLayout->addWidget(panes,1);workspace->addWidget(textWorkspace);workspace->setStretchFactor(1,1);workspace->setSizes({210,850});sectionSplitter->addWidget(workspace);sectionSplitter->setStretchFactor(1,2);sectionSplitter->setSizes({220,430});layout->addWidget(sectionSplitter,1);
        auto* workflowBar=new QHBoxLayout;workflowChoice=new QComboBox;workflowChoice->setObjectName("notepadWorkflow");workflowChoice->setMinimumContentsLength(18);workflowSource=new QComboBox;workflowSource->addItems({"Input","Output","Batch files…"});auto* run=new QPushButton("Execute");run->setObjectName("executeWorkflow");workflowBar->addWidget(new QLabel("Workflow"));workflowBar->addWidget(workflowChoice,1);workflowBar->addWidget(workflowSource);workflowBar->addWidget(run);auto* clear=new QPushButton("Clear");workflowBar->addWidget(clear);layout->addLayout(workflowBar);
        connect(run,&QPushButton::clicked,this,[this]{if(workflowSource->currentIndex()==2) prepareBatch();else runWorkflow(workflowSource->currentIndex()==1);});connect(clear,&QPushButton::clicked,this,[this]{input->clear();output->clear();outputIsEncrypted=false;clearVerificationIdentity();currentDocumentId.clear();currentDocumentTitle.clear();updateDocumentContext();});
        auto* files=new QHBoxLayout; auto* saveOutput=new QPushButton("Save output…"); auto* saveInput=new QPushButton("Save input…"); auto* importFile=new QPushButton("Import text file…"); auto* exportFile=new QPushButton("Export output…"); files->addWidget(saveOutput); files->addWidget(saveInput); files->addWidget(importFile); files->addWidget(exportFile); layout->addLayout(files);
        saveOutput->setProperty("requiresOutput",true); vaultMutationControls.append(saveOutput); vaultMutationControls.append(saveInput); saveOutput->setEnabled(false); exportFile->setEnabled(false); connect(output,&QPlainTextEdit::textChanged,saveOutput,[this,saveOutput,exportFile] {const bool has=!output->toPlainText().isEmpty(); saveOutput->setEnabled(has && !sessionReadOnly); exportFile->setEnabled(has);});
        connect(saveOutput,&QPushButton::clicked,this,[this] {saveVaultDocument(false);}); connect(saveInput,&QPushButton::clicked,this,[this] {saveVaultDocument(true);});
        connect(importFile,&QPushButton::clicked,this,[this] {const auto filename=chooseMessagePath(false); if(!filename.isEmpty()) loadMessageFile(filename);});
        connect(exportFile,&QPushButton::clicked,this,[this] {
            if(!outputIsEncrypted && QMessageBox::question(this,"Export readable output","This writes readable text or key material outside the encrypted vault. Continue?",QMessageBox::Save|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Save) return;
            const auto filename=chooseMessagePath(true); if(!filename.isEmpty()) saveOutputFile(filename);
        });
        notepadHost=new QWidget; notepadHostLayout=new QVBoxLayout(notepadHost); notepadHostLayout->setContentsMargins(0,0,0,0); notepadHostLayout->addWidget(page);
        notepadPlaceholder=new QWidget; auto* placeholderLayout=new QVBoxLayout(notepadPlaceholder); placeholderLayout->addStretch(); auto* message=new QLabel("Notepad is open in its own window. This vault, its profiles and saved documents are shared by both windows."); message->setWordWrap(true); placeholderLayout->addWidget(message);
        auto* openNotepad=new QPushButton("Show Notepad window"); openNotepad->setMinimumHeight(44); placeholderLayout->addWidget(openNotepad); connect(openNotepad,&QPushButton::clicked,this,[this] {showNotepad();}); auto* embedHint=new QLabel("To use one window, turn off “Open Notepad in its own window” in Vault settings."); embedHint->setWordWrap(true); placeholderLayout->addWidget(embedHint); placeholderLayout->addStretch(); notepadHostLayout->addWidget(notepadPlaceholder); notepadPlaceholder->hide();
        tabs->addTab(notepadHost,"Notepad");
    }

    void buildSavedNotes() {
        auto* page=new QWidget; auto* layout=new QVBoxLayout(page);
        auto* browser=new QWidget; auto* browserLayout=new QVBoxLayout(browser); browserLayout->setContentsMargins(0,0,7,0); browser->setMinimumWidth(200);
        auto* browserTitle=new QLabel("Saved in this vault"); browserTitle->setStyleSheet("font-weight: 600;"); browserLayout->addWidget(browserTitle);
        documentSearch=new QLineEdit; documentSearch->setPlaceholderText("Find a vault document…"); browserLayout->addWidget(documentSearch);
        documents=new QTableWidget(0,4); documents->setHorizontalHeaderLabels({"Document","Profile","Created","Updated"}); styleTable(documents); documents->setColumnWidth(0,280); documents->setColumnWidth(1,170); documents->setColumnWidth(2,155); documents->setColumnWidth(3,155); documents->setMinimumWidth(200); browserLayout->addWidget(documents,1);
        connect(documentSearch,&QLineEdit::textChanged,this,[this] {filterDocuments();}); connect(documents->horizontalHeader(),&QHeaderView::sortIndicatorChanged,this,[this] {QTimer::singleShot(0,this,[this] {filterDocuments();});});
        auto* documentActions=new QHBoxLayout; auto* openSaved=new QPushButton("Open"); auto* properties=new QPushButton("Properties…"); documentActions->addWidget(openSaved); documentActions->addWidget(properties); vaultMutationControls.append(properties); browserLayout->addLayout(documentActions);
        auto* otherActions=new QHBoxLayout; auto* fresh=new QPushButton("New"); auto* removeSaved=new QPushButton("Delete…"); otherActions->addWidget(fresh); otherActions->addWidget(removeSaved); vaultMutationControls.append(removeSaved); browserLayout->addLayout(otherActions);
        connect(fresh,&QPushButton::clicked,this,[this] {if((!input->toPlainText().isEmpty() || !output->toPlainText().isEmpty()) && QMessageBox::question(this,"New document","Discard unsaved Notepad text? Saved documents are unchanged.",QMessageBox::Discard|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Discard) return; input->clear(); output->clear(); currentDocumentId.clear(); currentDocumentTitle.clear(); currentDocumentProfile.clear(); outputIsEncrypted=false; clearVerificationIdentity(); updateDocumentContext(); tabs->setCurrentIndex(1); showNotepad(); input->setFocus();});
        auto* refresh=new QPushButton("Refresh vault files"); browserLayout->addWidget(refresh); connect(refresh,&QPushButton::clicked,this,[this] {refreshDocuments();});
        connect(openSaved,&QPushButton::clicked,this,[this] {openVaultDocument();}); connect(documents,&QTableWidget::cellDoubleClicked,this,[this](int,int) {openVaultDocument();});
        connect(properties,&QPushButton::clicked,this,[this] {documentPropertiesDialog();}); connect(removeSaved,&QPushButton::clicked,this,[this] {deleteVaultDocument();});
        connect(documents->horizontalHeader(),&QHeaderView::sortIndicatorChanged,this,[this] {QTimer::singleShot(0,this,[this] {filterDocuments();});});
        documents->setContextMenuPolicy(Qt::CustomContextMenu); connect(documents,&QWidget::customContextMenuRequested,this,[this](const QPoint& point) {
            const auto index=documents->indexAt(point); if(!index.isValid()) return; documents->selectRow(index.row());
            const auto documentId=documents->item(index.row(),0)->data(Qt::UserRole).toString(); const auto profileId=activeProfile;
            const auto copiedValue=documents->item(index.row(),index.column())->text(); const auto copiedRow=tableRowText(documents,index.row());
            QMenu menu; auto* open=menu.addAction("Open"); auto* props=menu.addAction("Properties…"); props->setEnabled(!sessionReadOnly && !pending); auto* copy=menu.addAction("Copy value"); auto* row=menu.addAction("Copy row"); auto* text=menu.addAction("Copy document text"); text->setEnabled(!pending); menu.addSeparator(); auto* remove=menu.addAction("Delete…"); remove->setEnabled(!sessionReadOnly && !pending);
            const auto selected=menu.exec(documents->viewport()->mapToGlobal(point)); if(!selected || ending || !unlocked) return;
            if(selected==copy) {copySessionText(copiedValue); return;} if(selected==row) {copySessionText(copiedRow); return;} if(pending) return;
            if(selected==text) {request("document_get",{{"document_id",documentId},{"profile_id",profileId}},[this](bool ok,const QJsonObject& data) {if(ok && unlocked && !ending) {copySessionText(data.value("text").toString()); statusBar()->showMessage("Document text copied.");}}); return;}
            int current=-1; for(int candidate=0;candidate<documents->rowCount();++candidate) if(documents->item(candidate,0)->data(Qt::UserRole).toString()==documentId) {current=candidate; break;}
            if(current<0) {statusBar()->showMessage("Document no longer appears in this view."); return;} documents->selectRow(current);
            if(selected==open) openVaultDocument(); else if(selected==props) documentPropertiesDialog(); else if(selected==remove) deleteVaultDocument();
        });
        layout->addWidget(browser,1); tabs->addTab(page,"Saved notes");
    }


    void clearVerificationIdentity() {if(verificationPopup) {verificationPopup->close(); verificationPopup.clear();} if(verificationIdentity) {verificationIdentity->clear(); verificationIdentity->hide();} statusBar()->setToolTip({});}

    void updateDocumentContext() {
        documentContext->setText(currentDocumentId.isEmpty()?"Unsaved text — stored only when you choose Save in vault.":"Opened vault document: "+currentDocumentTitle+". Changes are saved only when you choose Save in vault.");
    }

    void filterDocuments() {
        if(!documentSearch) return;
        const auto term=documentSearch->text();
        for(int row=0;row<documents->rowCount();++row) {bool matches=false; for(int column=0;column<documents->columnCount();++column) matches=matches||documents->item(row,column)->text().contains(term,Qt::CaseInsensitive); documents->setRowHidden(row,!matches);}
    }

    void refreshDocuments(std::function<void()> after = {}) {
        if(!unlocked || pending || workflowRunning) return;
        request("documents_list",{{"profile_id",activeProfile}},[this,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            profileDocumentCounts=data.value("profile_document_counts").toObject(); refreshIdentityCounts(); updateSessionStats();
            const auto selected=documents->currentRow()<0?QString():documents->item(documents->currentRow(),0)->data(Qt::UserRole).toString(); documents->setSortingEnabled(false); documents->setRowCount(0);
            for(const auto& value:data.value("documents").toArray()) {
                const auto document=value.toObject(); const int row=documents->rowCount(); documents->insertRow(row);
                auto* title=new TableItem(document.value("title").toString()); title->setData(Qt::UserRole,document.value("id").toString()); title->setData(Qt::UserRole+2,document.value("profile_id").toString()); title->setToolTip(title->text()+"\nProfile: "+(document.value("profile_id").toString().isEmpty()?QString("Unassigned"):profileTitle(document.value("profile_id").toString()))+"\nDocument ID: "+document.value("id").toString()); documents->setItem(row,0,title);
                documents->setItem(row,1,new TableItem(document.value("profile_id").toString().isEmpty()?QString("Unassigned"):profileTitle(document.value("profile_id").toString())));
                for(int column=2;column<=3;++column) {const auto timestamp=document.value(column==2?"created_at":"updated_at").toInteger(); const auto date=QDateTime::fromSecsSinceEpoch(timestamp).toLocalTime(); auto* item=new TableItem(date.toString("yyyy-MM-dd HH:mm")); item->setData(Qt::UserRole+20,timestamp); item->setToolTip(date.toString(Qt::ISODate)); documents->setItem(row,column,item);}
            }
            const auto oldRecent=recentDocuments->currentRow()<0?QString():recentDocuments->item(recentDocuments->currentRow(),0)->data(Qt::UserRole).toString();
            QList<QJsonObject> recent; for(const auto& value:data.value("documents").toArray()) recent.append(value.toObject());
            std::sort(recent.begin(),recent.end(),[](const QJsonObject& a,const QJsonObject& b) {const auto at=a.value("updated_at").toInteger(),bt=b.value("updated_at").toInteger(); return at==bt?a.value("id").toString()<b.value("id").toString():at>bt;});
            recentDocuments->setRowCount(0);
            for(int index=0;index<qMin(8,recent.size());++index) {const auto doc=recent[index]; recentDocuments->insertRow(index); auto* item=new TableItem(doc.value("title").toString()); item->setData(Qt::UserRole,doc.value("id").toString()); item->setToolTip(item->text()); recentDocuments->setItem(index,0,item); recentDocuments->setItem(index,1,new TableItem(QDateTime::fromSecsSinceEpoch(doc.value("updated_at").toInteger()).toLocalTime().toString("MM-dd HH:mm"))); if(doc.value("id").toString()==oldRecent) recentDocuments->selectRow(index);}
            documents->setSortingEnabled(true); filterDocuments(); for(int row=0;row<documents->rowCount();++row) if(documents->item(row,0)->data(Qt::UserRole).toString()==selected) documents->selectRow(row);
            if(after) after();
        });
    }

    void openVaultDocument(QString id = {}) {
        if(pending) return;
        if(id.isEmpty()) {if(documents->currentRow()<0) return; id=documents->item(documents->currentRow(),0)->data(Qt::UserRole).toString();}
        if(!testing && (!input->toPlainText().isEmpty() || !output->toPlainText().isEmpty()) && QMessageBox::question(this,"Open saved document","Replace the current unsaved Notepad text? Saved vault documents are unchanged.",QMessageBox::Open|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Open) return;
        request("document_get",{{"document_id",id},{"profile_id",activeProfile}},[this](bool ok,const QJsonObject& data) {
            if(!ok) return;
            currentDocumentId=data.value("id").toString(); currentDocumentTitle=data.value("title").toString(); currentDocumentProfile=data.value("profile_id").toString(); input->setPlainText(data.value("text").toString()); output->clear(); outputIsEncrypted=false; clearVerificationIdentity(); updateDocumentContext(); tabs->setCurrentIndex(1); showNotepad(); statusBar()->showMessage("Opened from encrypted vault. Edits are not saved automatically.");
        });
    }

    QComboBox* documentProfileChoice(const QString& selected) {
        auto* profile=new QComboBox; profile->addItem("Unassigned (visible in All)",QString()); for(const auto& value:profiles) {const auto item=value.toObject(); profile->addItem(item.value("name").toString(),item.value("id").toString());} profile->setCurrentIndex(qMax(0,profile->findData(selected))); return profile;
    }

    void saveVaultDocument(bool fromInput) {
        if(!unlocked || pending || sessionReadOnly) return;
        const auto text=fromInput?input->toPlainText():output->toPlainText();
        QDialog dialog(this); dialog.setWindowTitle("Save document in vault"); dialog.setMinimumWidth(530); auto* form=new QFormLayout(&dialog);
        auto* mode=new QComboBox; if(!currentDocumentId.isEmpty()) mode->addItem("Update opened document: "+currentDocumentTitle,true); mode->addItem("Save as a new document",false); form->addRow("Save action",mode);
        auto* title=new QLineEdit(currentDocumentId.isEmpty()?QString("untitled"):currentDocumentTitle); title->setMaxLength(120); form->addRow("Title",title);
        auto* profile=documentProfileChoice(currentDocumentId.isEmpty()?activeProfile:currentDocumentProfile); form->addRow("Profile",profile);
        auto* hint=new QLabel("Saved inside the encrypted vault. New names receive (1), (2), … if already used in that profile. Updating replaces only the document shown above."); hint->setWordWrap(true); form->addRow(hint);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); form->addRow(buttons);
        connect(mode,&QComboBox::currentIndexChanged,&dialog,[=,this] {const bool replacing=mode->currentData().toBool(); title->setText(replacing?currentDocumentTitle:QString("untitled")); profile->setCurrentIndex(qMax(0,profile->findData(replacing?currentDocumentProfile:activeProfile))); buttons->button(QDialogButtonBox::Save)->setText(replacing?"Update document":"Save new document");});
        buttons->button(QDialogButtonBox::Save)->setText(currentDocumentId.isEmpty()?"Save new document":"Update document"); connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        if(dialog.exec()!=QDialog::Accepted) return;
        request("document_save",{{"document_id",mode->currentData().toBool()?currentDocumentId:QString()},{"title",title->text()},{"text",text},{"profile_id",profile->currentData().toString()}},[this](bool ok,const QJsonObject& data) {if(ok) {currentDocumentId=data.value("id").toString(); currentDocumentTitle=data.value("title").toString(); currentDocumentProfile=data.value("profile_id").toString(); updateDocumentContext(); refreshDocuments([this] {statusBar()->showMessage("Saved “"+currentDocumentTitle+"” inside the encrypted vault.");});}});
    }

    void documentPropertiesDialog() {
        if(pending || sessionReadOnly || documents->currentRow()<0) return;
        const auto item=documents->item(documents->currentRow(),0); const auto id=item->data(Qt::UserRole).toString();
        QDialog dialog(this); dialog.setWindowTitle("Document properties"); dialog.setMinimumWidth(480); auto* form=new QFormLayout(&dialog); auto* title=new QLineEdit(item->text()); title->setMaxLength(120); form->addRow("Title",title); auto* profile=documentProfileChoice(item->data(Qt::UserRole+2).toString()); form->addRow("Profile",profile);
        auto* hint=new QLabel("Rename or move this saved document without changing its text. Duplicate titles receive a numeric suffix within the destination profile."); hint->setWordWrap(true); form->addRow(hint); auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); form->addRow(buttons); connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        if(dialog.exec()!=QDialog::Accepted) return;
        request("document_properties",{{"document_id",id},{"title",title->text()},{"profile_id",profile->currentData().toString()}},[this,id](bool ok,const QJsonObject& data) {if(ok) {if(currentDocumentId==id) {currentDocumentTitle=data.value("title").toString(); currentDocumentProfile=data.value("profile_id").toString(); updateDocumentContext();} refreshDocuments();}});
    }

    void deleteVaultDocument() {
        if(pending || documents->currentRow()<0) return;
        const auto id=documents->item(documents->currentRow(),0)->data(Qt::UserRole).toString();
        if(QMessageBox::question(this,"Delete saved document","Delete this document from the vault? Backups may retain older copies.",QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes) return;
        request("document_delete",{{"document_id",id},{"profile_id",activeProfile}},[this,id](bool ok,const QJsonObject&) {if(ok) {if(currentDocumentId==id) {currentDocumentId.clear(); currentDocumentTitle.clear(); updateDocumentContext();} refreshDocuments();}});
    }

    void alternativePasswordDialog(bool emergency) {
        const int index=emergency?1:0;
        if(!unlocked || pending || sessionReadOnly || !protectionMaster || !protectionOptionChecks[index]->isChecked()) return;
        QDialog dialog(this); dialog.setWindowTitle(emergency?"Emergency destruction password":"Dummy password"); dialog.setMinimumWidth(620); auto* form=new QFormLayout(&dialog);
        auto* warning=new QLabel(emergency?"Entering this password at unlock permanently overwrites this vault copy. Equal file size does not hide erasure. Backups, snapshots and SSD copies may remain. Requires PGPCrypt and its companion records.":"This password opens an empty, read-only view. Real data stays unchanged. File size, companion records and forensic evidence may reveal the dummy view; this does not guarantee plausible deniability."); warning->setWordWrap(true); form->addRow(warning);
        auto* pass=new QLineEdit; auto* confirm=new QLineEdit; for(auto* field:{pass,confirm}) {field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText|Qt::ImhNoAutoUppercase); limitNewPassword(field);} pass->setObjectName("alternativePassword"); confirm->setObjectName("alternativeConfirmation"); form->addRow("New password/passphrase",pass); form->addRow("Confirm",confirm); form->addRow(passwordStrength(pass));
        auto* hint=new QLabel("Saving replaces the previous password without asking for it. It must differ from the normal vault password and every other alternative. Nothing is changed until Save."); hint->setWordWrap(true); form->addRow(hint);
        QCheckBox* acknowledge=nullptr; if(emergency) {acknowledge=new QCheckBox("I understand this permanently destroys this vault copy."); form->addRow(acknowledge);}
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); form->addRow(buttons);
        auto update=[=] {buttons->button(QDialogButtonBox::Save)->setEnabled(pass->text()==confirm->text() && (!acknowledge || acknowledge->isChecked()));}; connect(pass,&QLineEdit::textChanged,&dialog,update); connect(confirm,&QLineEdit::textChanged,&dialog,update); if(acknowledge) connect(acknowledge,&QCheckBox::toggled,&dialog,update); update();
        connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); pass->setFocus();
        if(dialog.exec()!=QDialog::Accepted) {pass->clear(); confirm->clear(); return;}
        QJsonObject fields{{"new_password",pass->text()}}; pass->clear(); confirm->clear();
        request(emergency?"emergency_set":"dummy_set",fields,[this](bool saved,const QJsonObject&) {if(saved) statusBar()->showMessage("Password saved. Keep all companion files with this vault; outside edits can disarm this option.");});
    }

    void emergencyPasswordDialog() {alternativePasswordDialog(true);}
    void dummyPasswordDialog() {alternativePasswordDialog(false);}

    void expiryDialog() {
        if(!unlocked || pending || sessionReadOnly || !protectionMaster || !protectionOptionChecks[2]->isChecked()) return;
        QDialog dialog(this); dialog.setWindowTitle("Delete after inactivity"); dialog.setMinimumWidth(640); auto* form=new QFormLayout(&dialog);
        auto* warning=new QLabel("Measured from the last successful normal unlock. Once overdue, the next PGPCrypt unlock attempt overwrites this copy before decryption, including dummy-password attempts. No background deletion. Depends on the local clock and companion records; KeePassXC, age and backups do not enforce it."); warning->setWordWrap(true); form->addRow(warning);
        auto* duration=new QHBoxLayout; auto* count=new QSpinBox; count->setRange(1,1000); count->setValue(30); auto* unit=new QComboBox; unit->addItem("Days","days"); unit->addItem("Weeks","weeks"); unit->addItem("Months (30 days)","months"); unit->addItem("Years (365 days)","years"); duration->addWidget(count); duration->addWidget(unit); form->addRow("New inactivity period",duration);
        auto* limits=new QLabel("Saving replaces any previous period and restarts the deadline. Maximum 100 years. Existing settings are not displayed. Turn the option off to erase them."); limits->setWordWrap(true); form->addRow(limits);
        auto* acknowledge=new QCheckBox("I understand an overdue unlock attempt permanently overwrites this vault copy."); form->addRow(acknowledge);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); form->addRow(buttons);
        auto update=[=] {count->setMaximum(unit->currentData().toString()=="years"?100:1000); buttons->button(QDialogButtonBox::Save)->setEnabled(acknowledge->isChecked());}; connect(unit,&QComboBox::currentIndexChanged,&dialog,update); connect(acknowledge,&QCheckBox::toggled,&dialog,update); update();
        connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); if(dialog.exec()!=QDialog::Accepted) return;
        request("expiry_set",{{"expiry_count",count->value()},{"expiry_unit",unit->currentData().toString()}},[this](bool saved,const QJsonObject&) {if(saved) statusBar()->showMessage("Inactivity period saved. Keep an encrypted backup.");});
    }

    QString chooseMessagePath(bool save) {
        const bool armored=output->toPlainText().startsWith("-----BEGIN PGP ");
        const auto initial=save?QDir::home().filePath(armored?"message.asc":"message.txt"):QDir::homePath();
        QFileDialog dialog(this,save?"Export output outside vault":"Import text file",initial);
        dialog.setOption(QFileDialog::DontUseNativeDialog); dialog.setOption(QFileDialog::DontResolveSymlinks);
        dialog.setAcceptMode(save?QFileDialog::AcceptSave:QFileDialog::AcceptOpen);
        dialog.setFileMode(save?QFileDialog::AnyFile:QFileDialog::ExistingFile);
        dialog.setNameFilters({"Messages (*.asc *.pgp *.txt)","All files (*)"});
        if(!preferences.value("allow_removable_media").toBool()) {dialog.setProxyModel(new ExternalFileFilter(&dialog)); dialog.setSidebarUrls({QUrl::fromLocalFile(QDir::homePath()),QUrl::fromLocalFile("/")});}
        if(save) dialog.setDefaultSuffix(armored?"asc":"txt");
        if(dialog.exec()!=QDialog::Accepted || dialog.selectedFiles().isEmpty()) return {};
        const auto chosen=QFileInfo(dialog.selectedFiles().first()).absoluteFilePath();
        if(!ExternalFilePolicy::allowed(chosen,preferences.value("allow_removable_media").toBool())) {fail("Removable-media message access is off. Enable it in Vault settings to use this location."); return {};}
        return chosen;
    }

    bool loadMessageFile(const QString& filename) {
        const auto fileError=[this,&filename](const QString& message) {fail(message); if(activityLog) activityLog->record(ActivityEvent::OperationFailed,{"File: "+SafeActivityLog::field(QFileInfo(filename).fileName()),"Import: "+message});};
        if(!ExternalFilePolicy::allowed(filename,preferences.value("allow_removable_media").toBool())) {fileError("Message import from removable media is disabled in Vault settings."); return false;}
        const auto encoded=QFile::encodeName(filename);
        const int descriptor=::open(encoded.constData(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if(descriptor<0) {fileError("Cannot open message. Choose a readable file, not a symbolic link."); return false;}
        struct stat metadata{};
        if(::fstat(descriptor,&metadata)!=0 || !S_ISREG(metadata.st_mode) || metadata.st_size<0 || metadata.st_size>MaxMessageInput) {::close(descriptor); fileError("Choose a regular text message no larger than 4 MiB."); return false;}
        if(!preferences.value("allow_removable_media").toBool() && ExternalFilePolicy::removableDevice(metadata.st_dev)) {::close(descriptor); fileError("Message import from removable media is disabled."); return false;}
        QFile file;
        if(!file.open(descriptor,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)) {::close(descriptor); fileError("Cannot read message."); return false;}
        auto bytes=file.read(MaxMessageInput+1);
        if(file.error()!=QFileDevice::NoError || bytes.size()>MaxMessageInput || bytes.contains('\0')) {bytes.fill('\0'); fileError("Choose a UTF-8 text message no larger than 4 MiB."); return false;}
        QStringDecoder decoder(QStringDecoder::Utf8); QString text=decoder(bytes); bytes.fill('\0');
        if(decoder.hasError()) {fileError("This file is not UTF-8 text. Open an armored (.asc) message instead."); return false;}
        input->setPlainText(text); outputIsEncrypted=false; output->clear(); clearVerificationIdentity(); currentDocumentId.clear(); currentDocumentTitle.clear(); updateDocumentContext(); tabs->setCurrentIndex(1);
        statusBar()->showMessage("Imported into Input only. Choose Save input in vault to store it."); if(activityLog) activityLog->record(ActivityEvent::TextLoaded,{"File: "+SafeActivityLog::field(QFileInfo(filename).fileName())}); return true;
    }

    bool saveOutputFile(const QString& filename) {
        const auto fileError=[this,&filename](const QString& message) {fail(message); if(activityLog) activityLog->record(ActivityEvent::OperationFailed,{"File: "+SafeActivityLog::field(QFileInfo(filename).fileName()),"Export: "+message});};
        if(!ExternalFilePolicy::allowed(filename,preferences.value("allow_removable_media").toBool())) {fileError("Message export to removable media is disabled in Vault settings."); return false;}
        const auto target=QFileInfo(filename).absoluteFilePath();
        const auto vaultPath=activeVaultPath;
        for(const auto& reserved:QStringList{vaultPath,vaultPath+".lock",vaultPath+".pgpcrypt-emergency",vaultPath+".pgpcrypt-dummy",vaultPath+".pgpcrypt-protection",vaultPath+".pgpcrypt-expiry"}) {
            if(target==reserved || (QFileInfo::exists(target) && QFileInfo(target).canonicalFilePath()==QFileInfo(reserved).canonicalFilePath())) {fileError("Choose a message filename. The open vault and its support files cannot be overwritten."); return false;}
        }
        const auto encoded=QFile::encodeName(target); struct stat metadata{};
        if(::lstat(encoded.constData(),&metadata)==0) {
            if(!S_ISREG(metadata.st_mode)) {fileError("Choose a regular file, not a symbolic link."); return false;}
        } else if(errno!=ENOENT) {fileError("Cannot access the output location."); return false;}
        auto bytes=output->toPlainText().toUtf8();
        if(bytes.isEmpty() || bytes.size()>MaxMessageOutput) {bytes.fill('\0'); fileError("Output must contain text no larger than 4 MiB."); return false;}
        // A same-folder private temporary file plus rename keeps partial output
        // out of the final file. rename never follows a destination symlink.
        QTemporaryFile file(QFileInfo(target).absolutePath()+"/.pgpcrypt-message-XXXXXX");
        if(!file.open() || !file.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)) {bytes.fill('\0'); fileError("Cannot create a private output file. Choose a writable folder."); return false;}
        const bool written=file.write(bytes)==bytes.size(); bytes.fill('\0');
        if(!written || !file.flush() || ::fsync(file.handle())!=0) {fileError("Output could not be saved completely. Try another folder."); return false;}
        if(::rename(QFile::encodeName(file.fileName()).constData(),encoded.constData())!=0) {fileError("Cannot save output. Check folder permissions."); return false;}
        file.setAutoRemove(false);
        if(activityLog) activityLog->record(ActivityEvent::DocumentSaved,{"File: "+SafeActivityLog::field(QFileInfo(filename).fileName()),outputIsEncrypted?QString("Encrypted output"):QString("Readable output")});
        const int directory=::open(QFile::encodeName(QFileInfo(target).absolutePath()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        const bool synced=directory>=0 && ::fsync(directory)==0; if(directory>=0) ::close(directory);
        statusBar()->showMessage(synced?(outputIsEncrypted?"Encrypted message saved.":"Readable output saved outside the vault."):"Output saved, but folder sync failed. Keep a copy before shutting down.");
        return true;
    }

    void saveDefaultKey(const QString& fingerprint) {
        request("settings_set",{{"default_signing_key",fingerprint}},[this](bool ok,const QJsonObject&) {
            if(ok) { refreshKeys(); statusBar()->showMessage("Default signing key saved inside the encrypted vault"); }
        });
    }

    void updateSelection() {
        if(!selectionSummary) return;
        signer=signingChoice->currentData().toString(); QStringList recipients;
        for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) recipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
        selectionSummary->setText("Profile: "+profileTitle(activeProfile)+" · "+QString::number(recipients.size())+" recipient(s) selected"); selectionSummary->setToolTip(recipients.join("\n"));
        QString defaultLabel="Default: none";
        if(!defaultSigner.isEmpty()) {
            for(const auto& value:cachedKeys) {const auto key=value.toObject(); if(key.value("fingerprint").toString()==defaultSigner) defaultLabel="Default: "+keyIdentity(key)+" · "+defaultSigner.right(16);}
            if(signingChoice->findData(defaultSigner)<0) defaultLabel+=" (unavailable in this profile)";
        }
        defaultKeyLabel->setText(defaultLabel); defaultKeyLabel->setToolTip(defaultSigner);
    }

    QJsonObject messageContext() const {
        QJsonArray recipients; for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) recipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
        return {{"fingerprint",signer},{"recipients",recipients},{"profile_id",activeProfile}};
    }
    bool outputHasProof() const {
        const auto signers=outputProof.value("signer_details").toArray(); if(signers.isEmpty()) return false;
        for(const auto& value:signers) {const auto fingerprint=value.toObject().value("fingerprint").toString(); if(keyRecord(fingerprint).isEmpty() || !profileAllows(fingerprint)) return false;}
        auto bytes=output->toPlainText().toUtf8(); const auto digest=QCryptographicHash::hash(bytes,QCryptographicHash::Sha256); bytes.fill('\0'); return digest==outputProofDigest;
    }
    QStringList signerActivity(const QJsonObject& data) const {
        QStringList details; for(const auto& value:data.value("signer_details").toArray()) {const auto label=activityKey(value.toObject()); if(!label.isEmpty()) details.append(label);} return details;
    }
    void publishMessage(const QString& operation,const QJsonObject& data,const QString& source) {
        outputIsEncrypted=operation=="encrypt"; clearVerificationIdentity(); output->setPlainText(data.value("text").toString());
        if(operation=="verify" || operation=="decrypt") {
            QStringList displayed,status;
            for(const auto& value:data.value("signer_details").toArray()) {
                const auto key=value.toObject(); QStringList names; for(const auto& identity:key.value("identities").toArray()) names.append(identity.toString()); const auto name=names.isEmpty()?QString("No valid identity"):names.join("; "); const auto fp=key.value("fingerprint").toString();
                displayed.append("Verified signer: "+name+"\nCertificate key ID: "+key.value("key_id").toString()+"\nFingerprint: "+fp); status.append(name+" · "+fp);
            }
            if(!displayed.isEmpty()) {
                verificationIdentity->setText(displayed.join("\n\n")+"\nConfirm the fingerprint independently to establish identity."); verificationIdentity->show(); const auto summary="Valid signature: "+status.join("; "); statusBar()->showMessage(summary); statusBar()->setToolTip(summary);
                outputProof={{"signers",data.value("signers")},{"signer_details",data.value("signer_details")}}; auto bytes=output->toPlainText().toUtf8(); outputProofDigest=QCryptographicHash::hash(bytes,QCryptographicHash::Sha256); bytes.fill('\0');
            } else {verificationIdentity->setText(operation=="decrypt"?"Decrypted. No signature verified.":"No signature verified."); verificationIdentity->show(); statusBar()->showMessage(verificationIdentity->text());}
        } else statusBar()->showMessage(operation=="encrypt"?"Encrypted. Recipient identifiers may be visible in exports.":"Signed text is readable. The signature identifies the signing key.");
        if(operation=="verify") {if(activityLog) activityLog->record(ActivityEvent::VerificationPassed,signerActivity(data)); if(verificationPopup) verificationPopup->close(); verificationPopup=showVerificationDialog(this,true,data.value("signer_details").toArray(),cachedKeys,source);}
    }
    void verificationFailure(bool preserveOutput=false,const QString& original={}) {
        outputProof={}; outputProofDigest.clear(); clearVerificationIdentity(); if(preserveOutput) output->setPlainText(original); else output->clear();
        verificationIdentity->setText("Verification FAILED. No authenticated signer matched this message."); verificationIdentity->show(); statusBar()->showMessage(preserveOutput?"Verification FAILED. Output is unchanged.":"Verification FAILED");
        if(activityLog) activityLog->record(ActivityEvent::VerificationFailed,{"Signature invalid, unsupported, changed, or signer missing from this profile."});
        verificationPopup=showVerificationDialog(this,false,{},{});
    }
    void textAction(const QString& operation,std::function<void()> after={},bool fromOutput=false) {
        if(!unlocked || pending || workflowRunning || ending) return;
        if(operation=="sign" && signer.isEmpty()) {fail("Select a signing key on the notepad"); if(activityLog) activityLog->record(ActivityEvent::OperationFailed,{"Signing: no signing key selected."}); return;}
        const auto sourceText=fromOutput?output->toPlainText():input->toPlainText(); const bool wasEncrypted=outputIsEncrypted; const auto proof=fromOutput && outputHasProof()?outputProof:QJsonObject();
        if(fromOutput && sourceText.isEmpty()) {fail("Output is empty."); return;}
        if(operation=="verify" && !proof.isEmpty()) {auto result=proof; result.insert("text",sourceText); publishMessage(operation,result,"Previously authenticated message"); ++sessionOperations; if(after) after(); return;}
        auto fields=messageContext(); fields.insert("text",sourceText); if(!fromOutput) output->clear(); clearVerificationIdentity();
        performCrypto(operation,fields,[this,operation,after,fromOutput,sourceText,wasEncrypted](bool ok,const QJsonObject& data) {
            if(!ok) {if(operation=="verify") verificationFailure(fromOutput,sourceText); else if(fromOutput) {output->setPlainText(sourceText); outputIsEncrypted=wasEncrypted;} if(after) after(); return;}
            publishMessage(operation,data,fromOutput?"Output signature":"Input signature"); if(after) after();
        });
    }
    void refreshWorkflowChoices() {
        if(!workflowChoice) return;
        if(workflowEditor) workflowEditor->load(preferences.value("workflows").toArray());
        const auto selected=workflowChoice->currentText(); QSignalBlocker block(workflowChoice); workflowChoice->clear();
        for(const auto& value:preferences.value("workflows").toArray()) {const auto preset=value.toObject(); workflowChoice->addItem(preset.value("name").toString(),preset);}
        if(workflowChoice->count()==0) {workflowChoice->addItem("Create a workflow…",QJsonObject());} else workflowChoice->setCurrentIndex(qMax(0,workflowChoice->findText(selected)));
    }
    QJsonObject stepContext(const QJsonValue& value,const QJsonObject& inherited,QString* error) const {
        const auto step=workflowStep(value);const auto op=step.value("operation").toString();auto fields=inherited;
        if(!QStringList{"sign","verify","encrypt","decrypt"}.contains(op)){*error="Unsupported operation in workflow.";return {};}
        const auto mode=step.value("selection").toString("notepad");
        if(mode=="keys") {
            const auto selected=step.value("fingerprints").toArray();if(selected.isEmpty() || selected.size()>16){*error="Every explicit step needs 1–16 keys.";return {};}
            QSet<QString> unique;for(const auto& value:selected){const auto fp=value.toString();const auto key=keyRecord(fp);if(key.isEmpty() || unique.contains(fp)){*error="A workflow key is missing or duplicated. Edit the workflow.";return {};}unique.insert(fp);if((op=="sign"&&!key.value("can_sign").toBool()) || (op=="encrypt"&&!key.value("can_encrypt").toBool()) || (op=="decrypt"&&!key.value("has_secret").toBool())){*error="A selected key cannot perform the requested operation. Check its secret material, capabilities and expiry.";return {};}}
            fields=QJsonObject{{"profile_id",""}};
            if(op=="sign")fields.insert("signing_keys",selected);else if(op=="encrypt")fields.insert("recipients",selected);else {fields.insert("key_fingerprints",selected);if(op=="verify"&&step.value("require_all_signers").toBool())fields.insert("required_signers",selected);}
        } else if(mode!="notepad") {*error="Unsupported key-selection mode.";return {};}
        if(op=="sign"&&fields.value("fingerprint").toString().isEmpty()&&fields.value("signing_keys").toArray().isEmpty())*error="Choose a Notepad signing key or configure explicit signing keys.";
        if(op=="encrypt"&&fields.value("recipients").toArray().isEmpty())*error="Check Notepad recipients or configure explicit recipient keys.";
        return fields;
    }
    QString workflowError(const QJsonObject& preset,const QJsonObject& context) const {
        const auto steps=preset.value("steps").toArray();if(steps.isEmpty()||steps.size()>32)return "Choose a workflow with 1–32 steps.";
        for(int i=0;i<steps.size();++i){QString error;stepContext(steps[i],context,&error);if(!error.isEmpty())return "Step "+QString::number(i+1)+": "+error;}return {};
    }
    bool proofAllowed(const QJsonObject& proof,const QJsonObject& fields) const {
        const auto details=proof.value("signer_details").toArray();if(details.isEmpty())return false;
        const auto allowed=fields.value("key_fingerprints").toArray();QSet<QString> seen;const auto profileId=fields.value("profile_id").toString();
        for(const auto& value:details){const auto fp=value.toObject().value("fingerprint").toString();if(keyRecord(fp).isEmpty()||(!allowed.isEmpty()&&!allowed.contains(fp)))return false;if(!profileId.isEmpty()){bool found=false;for(const auto& profile:profiles){const auto p=profile.toObject();if(p.value("id").toString()==profileId&&p.value("fingerprints").toArray().contains(fp))found=true;}if(!found)return false;}seen.insert(fp);}
        for(const auto& fp:fields.value("required_signers").toArray()) {if(!seen.contains(fp.toString()))return false;}
        return true;
    }
    void runWorkflow(bool fromOutput,std::function<void()> after={}) {
        if(!unlocked||pending||workflowRunning||ending)return;
        const auto preset=workflowChoice->currentData().toJsonObject();const auto context=messageContext();const auto error=workflowError(preset,context);if(!error.isEmpty()){fail(error);return;}
        auto state=std::make_shared<WorkflowRun>();state->name=preset.value("name").toString();state->steps=preset.value("steps").toArray();state->context=context;state->text=fromOutput?output->toPlainText():input->toPlainText();state->originalOutput=output->toPlainText();state->originalEncrypted=outputIsEncrypted;state->fromOutput=fromOutput;state->after=std::move(after);if(fromOutput&&outputHasProof())state->proof=outputProof;
        if(state->text.isEmpty()){fail("Choose nonempty Input or Output.");return;}
        activeWorkflow=state;workflowRunning=true;syncBusyUi();clearVerificationIdentity();if(!fromOutput)output->clear();continueWorkflow(state);
    }
    void continueWorkflow(const std::shared_ptr<WorkflowRun>& state) {
        if(ending||!unlocked||activeWorkflow!=state)return;
        if(state->index>=state->steps.size()) {
            activeWorkflow.reset();auto result=state->lastResult;result.insert("text",state->text);
            if(state->batch){if(state->completion)state->completion(true,result);return;}
            workflowRunning=false;syncBusyUi();publishMessage(workflowOperation(state->steps.last()),result,"Workflow message");if(activityLog)activityLog->record(ActivityEvent::OperationComplete,{"Workflow: "+state->name,"All "+QString::number(state->steps.size())+" steps completed."});statusBar()->showMessage("Workflow completed: "+state->name);if(state->after)state->after();return;
        }
        const auto operation=workflowOperation(state->steps[state->index]);QString configurationError;auto fields=stepContext(state->steps[state->index],state->context,&configurationError);
        statusBar()->showMessage("Workflow "+state->name+": step "+QString::number(state->index+1)+" / "+QString::number(state->steps.size())+" — "+operation+". Lock to cancel.");
        auto completed=[this,state,operation](bool ok,const QJsonObject& data){
            if(ending||!unlocked||activeWorkflow!=state)return;
            if(!ok){if(state->batch&&activeBatch&&data.value("_cancelled").toBool())activeBatch->stopRequested=true;activeWorkflow.reset();const auto reason="Stopped at step "+QString::number(state->index+1)+" ("+operation+"). No intermediate result saved.";if(activityLog)activityLog->record(ActivityEvent::OperationFailed,{"Workflow: "+state->name,reason});
                if(state->batch){if(state->completion)state->completion(false,QJsonObject{{"reason",reason}});return;}
                workflowRunning=false;syncBusyUi();if(state->fromOutput){output->setPlainText(state->originalOutput);outputIsEncrypted=state->originalEncrypted;}else output->clear();clearVerificationIdentity();if(operation=="verify")verificationFailure(state->fromOutput,state->originalOutput);statusBar()->showMessage(reason);if(state->after)state->after();return;
            }
            state->text=data.value("text").toString();state->lastResult=data;state->proof={};if((operation=="verify"||operation=="decrypt")&&!data.value("signer_details").toArray().isEmpty())state->proof=QJsonObject{{"signers",data.value("signers")},{"signer_details",data.value("signer_details")}};
            if(operation=="verify"&&activityLog&&(state->batch||state->index+1<state->steps.size()))activityLog->record(ActivityEvent::VerificationPassed,signerActivity(data));
            ++state->index;continueWorkflow(state);
        };
        if(!configurationError.isEmpty()){completed(false,{});return;}
        if(operation=="verify"&&proofAllowed(state->proof,fields)){auto result=state->proof;result.insert("text",state->text);++sessionOperations;completed(true,result);return;}
        fields.insert("text",state->text);performCrypto(operation,fields,completed);
    }

    bool batchReserved(const QString& path) const {
        const auto resolve=[](const QString& path){const QFileInfo file(path);return QDir(QFileInfo(file.absolutePath()).canonicalFilePath()).filePath(file.fileName());};
        for(const auto& suffix:QStringList{"",".lock",".pgpcrypt-emergency",".pgpcrypt-dummy",".pgpcrypt-protection",".pgpcrypt-expiry"}) if(resolve(path)==resolve(activeVaultPath+suffix))return true;
        return false;
    }
    AutomationFiles::Saved saveBatchFile(const QString& path,QByteArray bytes) {
        if(batchReserved(path)){bytes.fill('\0');return {false,"This filename is reserved for the open vault or its support records."};}
        return AutomationFiles::writeNew(path,bytes,preferences.value("allow_removable_media").toBool());
    }

    void prepareBatch() {
        if(!unlocked||pending||workflowRunning||ending)return;
        const auto preset=workflowChoice->currentData().toJsonObject();const auto context=messageContext();const auto error=workflowError(preset,context);if(!error.isEmpty()){fail(error);return;}
        QFileDialog picker(this,"Choose batch message files",QDir::homePath());picker.setOption(QFileDialog::DontUseNativeDialog);picker.setOption(QFileDialog::DontResolveSymlinks);picker.setFileMode(QFileDialog::ExistingFiles);picker.setNameFilters({"Text and armored PGP messages (*.txt *.asc *.pgp)","All files (*)"});
        if(!preferences.value("allow_removable_media").toBool()){picker.setProxyModel(new ExternalFileFilter(&picker));picker.setSidebarUrls({QUrl::fromLocalFile(QDir::homePath()),QUrl::fromLocalFile("/")});}
        if(picker.exec()!=QDialog::Accepted||picker.selectedFiles().isEmpty())return;
        const auto files=picker.selectedFiles();if(files.size()>64){fail("Choose at most 64 files per batch.");return;}
        QDialog dialog(this);dialog.setWindowTitle("Preview batch — "+preset.value("name").toString());dialog.resize(920,600);auto* layout=new QVBoxLayout(&dialog);auto* hint=new QLabel("Each input is one independent job. Only its final successful result is saved; existing files are never overwritten. Every finished job opens a result window. Lock cancels remaining jobs; completed exports remain.");hint->setWordWrap(true);layout->addWidget(hint);
        auto* form=new QFormLayout;auto* directory=new QLineEdit(QDir::homePath());auto* location=new QWidget;auto* locationLayout=new QHBoxLayout(location);locationLayout->setContentsMargins(0,0,0,0);auto* browse=new QPushButton("Browse…");locationLayout->addWidget(directory,1);locationLayout->addWidget(browse);form->addRow("Destination folder",location);auto* pattern=new QLineEdit(preset.value("output_pattern").toString("{stem}-{index}.processed"));form->addRow("Filename pattern",pattern);layout->addLayout(form);
        auto* table=new QTableWidget(files.size(),2);table->setHorizontalHeaderLabels({"Input file","Destination filename — editable"});table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);table->horizontalHeader()->setStretchLastSection(true);table->setColumnWidth(0,360);for(int row=0;row<files.size();++row){auto* item=new QTableWidgetItem(QFileInfo(files[row]).fileName());item->setToolTip(files[row]);item->setFlags(item->flags()&~Qt::ItemIsEditable);table->setItem(row,0,item);table->setItem(row,1,new QTableWidgetItem);}layout->addWidget(table,1);
        auto names=[&]{for(int row=0;row<files.size();++row)table->item(row,1)->setText(AutomationFiles::expand(pattern->text(),files[row],row+1,preset.value("name").toString()));};names();connect(pattern,&QLineEdit::textEdited,&dialog,names);
        auto* tokens=new QLabel("Tokens: {stem}, {name}, {ext}, {index}, {workflow}. Text/armored messages only; Encrypt/Sign input is limited to 1 MiB, message files to 4 MiB. No plaintext temporary input files are created.");tokens->setWordWrap(true);layout->addWidget(tokens);
        const bool encrypted=workflowOperation(preset.value("steps").toArray().last())=="encrypt";auto* disclosure=new QLabel(encrypted?"Final results are encrypted PGP messages. Destination filenames remain visible to the operating system.":"Final results may be readable text, signed text or key material outside vault encryption. Review the destination folder and filenames before executing.");disclosure->setWordWrap(true);layout->addWidget(disclosure);
        auto* keepGoing=new QCheckBox("Continue with other files when a job fails");keepGoing->setChecked(true);layout->addWidget(keepGoing);auto* status=new QLabel;status->setTextFormat(Qt::PlainText);status->setWordWrap(true);layout->addWidget(status);
        connect(browse,&QPushButton::clicked,&dialog,[&]{QFileDialog folder(&dialog,"Batch destination folder",directory->text());folder.setOption(QFileDialog::DontUseNativeDialog);folder.setOption(QFileDialog::DontResolveSymlinks);folder.setFileMode(QFileDialog::Directory);folder.setOption(QFileDialog::ShowDirsOnly);if(!preferences.value("allow_removable_media").toBool())folder.setProxyModel(new ExternalFileFilter(&folder));if(folder.exec()==QDialog::Accepted&&!folder.selectedFiles().isEmpty())directory->setText(folder.selectedFiles().first());});
        QList<BatchJob> jobs;auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);buttons->button(QDialogButtonBox::Ok)->setText("Execute batch");layout->addWidget(buttons);connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);connect(buttons,&QDialogButtonBox::accepted,&dialog,[&]{
            const auto folder=QFileInfo(directory->text()).canonicalFilePath();if(folder.isEmpty()||!QFileInfo(folder).isDir()){status->setText("Choose an existing destination folder.");return;}QSet<QString> targets;QList<BatchJob> planned;qint64 total=0;
            for(int row=0;row<files.size();++row){const QFileInfo input(files[row]);const auto name=table->item(row,1)->text();const auto target=QDir(folder).filePath(name);if(!AutomationFiles::safeName(name)||targets.contains(target)||batchReserved(target)){status->setText("Every output needs a unique filename without folders or control characters.");return;}const auto encoded=QFile::encodeName(target);struct stat info{};if(::lstat(encoded.constData(),&info)==0||errno!=ENOENT){status->setText("Destination exists or cannot be inspected: "+name+". Choose a new name.");return;}if(!ExternalFilePolicy::allowed(files[row],preferences.value("allow_removable_media").toBool())||!ExternalFilePolicy::allowed(target,preferences.value("allow_removable_media").toBool())){status->setText("This batch includes a location blocked by the removable-media setting.");return;}if(input.size()<0||input.size()>AutomationFiles::MaxBytes){status->setText("Every input must be at most 4 MiB.");return;}total+=input.size();if(total>64*1024*1024){status->setText("Choose at most 64 MiB of input per batch.");return;}targets.insert(target);planned.append({input.absoluteFilePath(),target});}jobs=planned;dialog.accept();
        });
        if(dialog.exec()!=QDialog::Accepted||ending||!unlocked)return;
        startBatch(preset,context,jobs,keepGoing->isChecked());
    }
    void startBatch(const QJsonObject& preset,const QJsonObject& context,const QList<BatchJob>& jobs,bool continueOnError,std::function<void()> after={}) {
        if(jobs.isEmpty()||pending||workflowRunning||ending)return;
        auto batch=std::make_shared<BatchRun>();batch->preset=preset;batch->context=context;batch->jobs=jobs;batch->continueOnError=continueOnError;batch->after=std::move(after);activeBatch=batch;workflowRunning=true;syncBusyUi();continueBatch(batch);
    }
    void continueBatch(const std::shared_ptr<BatchRun>& batch) {
        if(ending||!unlocked||activeBatch!=batch||activeWorkflow)return;
        if(batch->index>=batch->jobs.size()||batch->stopRequested) {const auto summary=QString("Batch complete: %1 succeeded, %2 failed, %3 skipped.").arg(batch->success).arg(batch->failed).arg(batch->jobs.size()-batch->success-batch->failed);activeBatch.reset();workflowRunning=false;syncBusyUi();statusBar()->showMessage(summary);if(activityLog)activityLog->record(ActivityEvent::OperationComplete,{summary});if(batch->after)batch->after();return;}
        int visible=0;for(const auto& window:jobWindows)if(window)++visible;if(visible>=16||retainedJobBytes>28*1024*1024){statusBar()->showMessage("Batch paused: close a completed result window to continue (save any unsaved result before closing).");return;}
        const auto job=batch->jobs[batch->index];QString text;const auto error=AutomationFiles::read(job.inputPath,preferences.value("allow_removable_media").toBool(),&text);
        if(!error.isEmpty()){finishBatchJob(batch,false,QJsonObject{{"reason",error}});return;}
        auto run=std::make_shared<WorkflowRun>();run->name=batch->preset.value("name").toString();run->steps=batch->preset.value("steps").toArray();run->context=batch->context;run->text=text;run->batch=true;run->completion=[this,batch](bool ok,const QJsonObject& result){finishBatchJob(batch,ok,result);};activeWorkflow=run;
        if(activityLog)activityLog->record(ActivityEvent::TextLoaded,{"Batch job "+QString::number(batch->index+1)+" / "+QString::number(batch->jobs.size()),"File: "+SafeActivityLog::field(QFileInfo(job.inputPath).fileName())});
        continueWorkflow(run);
    }
    void finishBatchJob(const std::shared_ptr<BatchRun>& batch,bool ok,QJsonObject result) {
        if(ending||activeBatch!=batch)return;
        const auto job=batch->jobs[batch->index];const bool encrypted=workflowOperation(batch->preset.value("steps").toArray().last())=="encrypt";const bool authenticated=ok;QString report=result.value("reason").toString();
        if(ok){const auto saved=saveBatchFile(job.outputPath,result.value("text").toString().toUtf8());ok=saved.committed;report=saved.error.isEmpty()?"All steps succeeded. Final output saved.":saved.error;}
        if(ok)++batch->success;else{++batch->failed;if(!authenticated){result.remove("text");result.remove("signer_details");}}
        if(activityLog)activityLog->record(ok?ActivityEvent::DocumentSaved:ActivityEvent::OperationFailed,{"File: "+SafeActivityLog::field(QFileInfo(job.inputPath).fileName()),"Destination: "+SafeActivityLog::field(QFileInfo(job.outputPath).fileName()),report});
        showBatchResult(job,batch->index+1,ok,result,report,encrypted,authenticated);++batch->index;
        if(!ok&&!batch->continueOnError) {batch->index=batch->jobs.size();}
        QTimer::singleShot(0,this,[this,batch]{continueBatch(batch);});
    }
    void showBatchResult(const BatchJob& job,int number,bool ok,const QJsonObject& result,const QString& report,bool encrypted,bool authenticated) {
        auto* window=new QDialog(this);window->setObjectName("batchJobResult");window->setAttribute(Qt::WA_DeleteOnClose);window->setWindowTitle("Job "+QString::number(number)+(ok?" completed — ":" failed — ")+QFileInfo(job.inputPath).fileName());window->resize(780,520);auto* layout=new QVBoxLayout(window);auto* heading=new QLabel((ok?"COMPLETED — ":"FAILED — ")+report);heading->setTextFormat(Qt::PlainText);heading->setWordWrap(true);layout->addWidget(heading);auto* location=new QLabel("Input: "+QFileInfo(job.inputPath).fileName()+"\n"+(ok?"Saved to: ":"Requested destination: ")+job.outputPath);location->setTextFormat(Qt::PlainText);location->setWordWrap(true);layout->addWidget(location);
        auto* body=editor({},true);body->setPlainText(authenticated?result.value("text").toString():QString());body->setUndoRedoEnabled(false);layout->addWidget(body,1);const auto bytes=body->toPlainText().toUtf8().size();retainedJobBytes+=bytes;
        auto* actions=new QHBoxLayout;auto* copy=new QPushButton("Copy all");copy->setEnabled(authenticated);actions->addWidget(copy);connect(copy,&QPushButton::clicked,window,[body]{copySessionText(body->toPlainText());});auto* save=new QPushButton("Save another copy…");save->setEnabled(authenticated);actions->addWidget(save);connect(save,&QPushButton::clicked,window,[this,window,body,job,encrypted]{QFileDialog dialog(window,encrypted?"Save encrypted result":"Save readable result outside vault",job.outputPath);dialog.setOption(QFileDialog::DontUseNativeDialog);dialog.setOption(QFileDialog::DontResolveSymlinks);dialog.setAcceptMode(QFileDialog::AcceptSave);dialog.setOption(QFileDialog::DontConfirmOverwrite);if(!preferences.value("allow_removable_media").toBool())dialog.setProxyModel(new ExternalFileFilter(&dialog));if(dialog.exec()!=QDialog::Accepted||dialog.selectedFiles().isEmpty()||ending)return;const auto saved=saveBatchFile(dialog.selectedFiles().first(),body->toPlainText().toUtf8());QMessageBox::information(window,saved.committed?"Result saved":"Result not saved",saved.error.isEmpty()?"Saved a separate copy.":saved.error);});
        if(authenticated&&!result.value("signer_details").toArray().isEmpty()){auto* verify=new QPushButton("Verified signers…");actions->addWidget(verify);connect(verify,&QPushButton::clicked,window,[this,window,result]{showVerificationDialog(window,true,result.value("signer_details").toArray(),cachedKeys,"Batch job signature");});}
        auto* stop=new QPushButton("Stop after current job");stop->setProperty("batchStop",true);stop->setEnabled(activeBatch!=nullptr);actions->addWidget(stop);connect(stop,&QPushButton::clicked,window,[this,stop]{if(activeBatch){activeBatch->stopRequested=true;stop->setEnabled(false);statusBar()->showMessage("The batch will stop after the current job; remaining files will be skipped.");if(!activeWorkflow){auto batch=activeBatch;QTimer::singleShot(0,this,[this,batch]{continueBatch(batch);});}}});
        auto* close=new QPushButton("Close");actions->addWidget(close);connect(close,&QPushButton::clicked,window,&QDialog::close);layout->addLayout(actions);jobWindows.removeIf([](const QPointer<QDialog>& item){return item.isNull();});jobWindows.append(window);
        connect(window,&QObject::destroyed,this,[this,bytes]{retainedJobBytes=qMax<qint64>(0,retainedJobBytes-bytes);if(activeBatch&&!activeWorkflow&&!ending){auto batch=activeBatch;QTimer::singleShot(0,this,[this,batch]{continueBatch(batch);});}});window->show();
    }

    void performCrypto(const QString& operation,QJsonObject fields,Reply done,int attempt=0,QPointer<QLocalSocket> peer={},bool remoteCall=false,std::shared_ptr<QHash<QString,int>> tries={}) {
        if(!tries) tries=std::make_shared<QHash<QString,int>>();
        if(remoteCall && (!peer || peer->state()!=QLocalSocket::ConnectedState)) {done(false,{}); return;}
        request(operation,fields,[this,operation,fields,done,attempt,peer,remoteCall,tries](bool ok,const QJsonObject& data) mutable {
            const auto errorCode=data.value("_error_code").toString();
            const auto needed=data.value("_required_key").toString();const auto promptKey=errorCode=="vault_auth_required"?QString("vault"):needed.isEmpty()?QString("private"):needed;
            if(!ok && (errorCode=="password_required" || errorCode=="vault_auth_required") && tries->value(promptKey)<6) {
                ++(*tries)[promptKey];
                const bool vaultAuth=errorCode=="vault_auth_required";const auto requiredKey=needed;
                bool accepted=true; QString pass;
                if(testing) pass=vaultAuth?"disposable Qt fixture passphrase":testKdbx?"":"x";
                else {
                    QDialog dialog(this); dialog.setWindowTitle(vaultAuth?"Confirm vault password":"Unlock private key");
                    auto* form=new QFormLayout(&dialog); if(!requiredKey.isEmpty()){auto* keyLabel=new QLabel(activityKey(keyRecord(requiredKey)));keyLabel->setTextFormat(Qt::PlainText);keyLabel->setWordWrap(true);form->addRow(keyLabel);} auto* prompt=new QLabel(vaultAuth?"Confirm the normal vault password to display unprotected private key material.":operation=="add_subkeys"?"Enter the primary private-key password to certify the complete subkey plan.":operation.contains("private_export")?"Enter the private-key password/passphrase. Export keeps its existing packet protection.":"Enter the private-key password/passphrase to complete this operation."); prompt->setWordWrap(true); form->addRow(prompt);
                    auto* entry=new QLineEdit; entry->setEchoMode(QLineEdit::Password); entry->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText|Qt::ImhNoAutoUppercase); form->addRow("Password/passphrase",entry);
                    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel); form->addRow(buttons);
                    connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); connect(entry,&QLineEdit::returnPressed,&dialog,&QDialog::accept);
                    QTimer timeout; timeout.setSingleShot(true);
                    if(remoteCall) {if(!peer || peer->state()!=QLocalSocket::ConnectedState) {done(false,{}); return;} connect(peer,&QLocalSocket::disconnected,&dialog,&QDialog::reject); connect(&timeout,&QTimer::timeout,&dialog,&QDialog::reject); timeout.start(60000);}
                    entry->setFocus(); accepted=dialog.exec()==QDialog::Accepted; pass=entry->text(); entry->clear();
                }
                if(!accepted || ending || (remoteCall && (!peer || peer->state()!=QLocalSocket::ConnectedState))) {statusBar()->showMessage("Operation cancelled"); done(false,QJsonObject{{"_cancelled",true}}); return;}
                if(!vaultAuth&&!requiredKey.isEmpty()){auto credentials=fields.value("key_passwords").toArray();bool replaced=false;for(int i=0;i<credentials.size();++i)if(credentials[i].toObject().value("fingerprint").toString()==requiredKey){credentials[i]=QJsonObject{{"fingerprint",requiredKey},{"password",pass}};replaced=true;break;}if(!replaced)credentials.append(QJsonObject{{"fingerprint",requiredKey},{"password",pass}});fields.insert("key_passwords",credentials);}else fields.insert(vaultAuth?"vault_password":"password",pass); pass.fill(QChar('\0')); performCrypto(operation,fields,done,attempt+1,peer,remoteCall,tries); return;
            }
            if(!ok && (errorCode=="password_required" || errorCode=="vault_auth_required")) {if(activityLog) activityLog->record(ActivityEvent::OperationFailed,activityContext(operation,fields)+QStringList{activityReason({},errorCode)}); fail(operation.contains("private_export")?"Authorization failed. Export needs the password for every protected secret packet.":"Could not unlock the private key.");}
            done(ok,data);
        });
    }

    void rpcProbe(const QJsonObject& object,bool expected,std::function<void()> after) {
        auto* socket=new QLocalSocket(this); auto response=std::make_shared<QByteArray>(); auto finished=std::make_shared<bool>(false);
        auto* timeout=new QTimer(socket); timeout->setSingleShot(true); timeout->start(10000);
        connect(timeout,&QTimer::timeout,this,[this,socket] {socket->abort(); fail("Local Qubes broker probe timed out");});
        connect(socket,&QLocalSocket::readyRead,this,[socket,response] {*response+=socket->readAll();});
        connect(socket,&QLocalSocket::disconnected,this,[this,socket,response,finished,expected,after] {
            if(*finished) return;
            *finished=true; const auto result=QJsonDocument::fromJson(*response).object();
            if(result.value("ok").toBool()!=expected || (expected && !result.value("data").toObject().value("text").toString().contains("BEGIN PGP SIGNED MESSAGE"))) {socket->deleteLater(); fail("Local Qubes broker approval/denial failed"); return;}
            socket->deleteLater(); QTimer::singleShot(1100,this,after);
        });
        connect(socket,&QLocalSocket::connected,this,[socket,object] {auto bytes=QJsonDocument(object).toJson(QJsonDocument::Compact);bytes.append('\n');socket->write(bytes);});
        socket->connectToServer(rpcPath);
    }

    bool testKeyCreationDefaults() {
        bool valid=false;
        QTimer::singleShot(0,this,[this,&valid] {
            auto* dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget()); if(!dialog) return;
            QList<QCheckBox*> capabilities; QCheckBox* expiry=nullptr;
            auto* capabilityBox=dialog->findChild<QWidget*>("keyCapabilities"); if(capabilityBox) capabilities=capabilityBox->findChildren<QCheckBox*>(); expiry=dialog->findChild<QCheckBox*>("primaryExpiryEnabled");
            valid=capabilities.size()==4 && expiry && !expiry->isChecked();
            for(auto* check:capabilities) valid=valid && check->isChecked() && check->parentWidget()==capabilities.first()->parentWidget();
            const auto* date=dialog->findChild<QDateTimeEdit*>("primaryExpiry"); const auto* plan=dialog->findChild<QGroupBox*>("customSubkeys"); valid=valid && date && !date->isEnabled() && plan && !plan->isChecked(); dialog->reject();
        });
        createKeyDialog(); if(!valid) fail("Key capability alignment/defaults or expiry default failed"); return valid;
    }

    bool testNotepadWindow() {
        if(notepadPopout || !tabs->widget(1)->isAncestorOf(input)) {fail("Notepad is not embedded by default"); return false;}
        auto* sameInput=input; input->setPlainText("Shared Notepad text fixture"); tabs->setCurrentIndex(1);
        auto value=preferences; value.insert("notepad_popout",false); applyPreferences(value);
        if(input!=sameInput || !tabs->widget(1)->isAncestorOf(input) || input->toPlainText()!="Shared Notepad text fixture") {fail("Embedding Notepad lost its shared editor"); return false;}
        value.insert("notepad_popout",true); applyPreferences(value);
        if(input!=sameInput || !notepadWindow->isAncestorOf(input) || input->toPlainText()!="Shared Notepad text fixture") {fail("Detaching Notepad lost its shared editor"); return false;}
        notepadWindow->close(); if(notepadWindow->isVisible() || tabs->currentIndex()!=0 || input->toPlainText()!="Shared Notepad text fixture") {fail("Closing Notepad lost text or failed to return to Keys"); return false;}
        value.insert("notepad_popout",false); applyPreferences(value); input->clear(); return true;
    }

    bool testSafeActivity() {
        if(!activityLog || activityLog->document()->maximumBlockCount()!=200) {fail("Activity log is not bounded"); return false;}
        for(int index=0;index<220;++index) activityLog->record(ActivityEvent::OperationComplete);
        activityLog->record(ActivityEvent::OperationFailed,{"Key: Desktop fixture ["+testFingerprint+"]",QString("malicious\nrow\x1b[31m")+QChar(0x202e)}); activityLog->setWarningsOnly(true);
        const auto text=activityLog->toPlainText();
        if(activityLog->document()->blockCount()>200 || !activityLog->warningsOnly() || !text.contains(testFingerprint) || text.contains(QChar(0x1b)) || text.contains(QChar(0x202e)) || text.contains(activeVaultPath) || text.contains("dummy",Qt::CaseInsensitive) || text.contains("protection",Qt::CaseInsensitive) || text.contains("disposable Qt fixture passphrase") || text.contains("BEGIN PGP PRIVATE KEY") || text.contains("Qt signature fixture")) {fail("Activity history leaked details or exceeded its bound"); return false;}
        activityLog->setWarningsOnly(false); resetActivity();
        if(activityLog->document()->blockCount()!=1 || !activityLog->toPlainText().contains("READY")) {fail("Clearing activity did not restore Ready"); return false;}
        // Timer off still clears our last copy; do not erase unrelated text.
        copySessionText("disposable clipboard fixture"); clearSessionClipboard();
        if(!qApp->clipboard()->text().isEmpty()) {fail("Session clipboard cleanup failed with timer off"); return false;}
        for(const auto& id:QStringList{"ruby-dark","ruby-light","terminal-green","cyberpunk"}) {auto value=preferences; value.insert("theme",id); applyPreferences(value); if(qApp->palette().color(QPalette::Text).lightness()==qApp->palette().color(QPalette::Base).lightness()) {fail("Theme text has no contrast"); return false;}}
        return true;
    }

    bool testReadOnlyControls() {
        const auto ordinaryStatus=sessionWarning->text();
        sessionReadOnly=true; applyReadOnlyUi();
        bool safe=sessionWarning->text()==ordinaryStatus && !sessionWarning->text().contains("read-only",Qt::CaseInsensitive) && !sessionWarning->text().contains("dummy",Qt::CaseInsensitive) && !sessionWarning->text().contains("protection",Qt::CaseInsensitive) && input->isEnabled() && pasteInput->isEnabled() && rememberVaultsCheck->isEnabled() && !profileTabs->isTabEnabled(profileTabs->count()-1);
        for(auto* button:navigationButtons) safe=safe && button->isEnabled();
        for(auto* control:vaultMutationControls) safe=safe && !control->isEnabled();
        sessionReadOnly=false; applyReadOnlyUi(); applyPreferences(preferences);
        if(!safe) {fail("Read-only view left vault edits enabled or disabled Notepad/navigation"); return false;}
        return true;
    }

    void testClipboardImport(std::function<void()> after) {
        copyPublicKey(testFingerprint,[this,after] {
            importText->setPlainText("This old editor content must be replaced");
            importClipboardKey([this,after] {
                if(!qApp->clipboard()->text().isEmpty() || !importText->toPlainText().isEmpty() || cachedKeys.size()!=1 || !keyRecord(testFingerprint).value("has_secret").toBool()) {fail("Clipboard import did not clear/replace/import or lost the existing private key"); return;}
                after();
            });
        });
    }

    void testSettingsAndQubes(std::function<void()> after) {
        if(!testReadOnlyControls() || !testNotepadWindow() || !testSafeActivity() || !testKeyCreationDefaults()) return;
        if(autoLock || focusLock || sessionLock || clipboardSeconds!=0 || tabs->count()!=6 || navigationButtons.size()!=6) {fail("New-vault default settings or notes removal failed"); return;}
        QEvent deactivate(QEvent::ApplicationDeactivate); QCoreApplication::sendEvent(qApp,&deactivate);
        if(ending) {fail("Focus loss locked with opt-in disabled"); return;}
        if(keys->contextMenuPolicy()!=Qt::CustomContextMenu || recipientChoices->contextMenuPolicy()!=Qt::CustomContextMenu || profileMembers->contextMenuPolicy()!=Qt::CustomContextMenu) {fail("Key quick-action menus are missing"); return;}
        copyPublicKey(testFingerprint,[this,after] {
            if(!qApp->clipboard()->text().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----") || qApp->clipboard()->text().contains("PRIVATE KEY BLOCK")) {fail("Copy public key did not copy public armor"); return;}
            qApp->clipboard()->clear();
            QJsonObject value{{"auto_lock",false},{"lock_on_focus_loss",false},{"lock_on_session_events",false},{"clipboard_clear_seconds",0},{"theme","dark"},{"qubes_rpc",true},{"notepad_popout",true},{"show_session_stats",true},{"activity_welcome","+-- PGPCrypt --+\n|  fixture   |\n+------------+"}};
            request("settings_set",{{"preferences",value}},[this,after](bool ok,const QJsonObject& data) {
                if(!ok) {return;} applyPreferences(data.value("preferences").toObject());
                if(!rpcServer.isListening() || qApp->palette().color(QPalette::Window).lightness()>100 || !sessionStats->text().contains("FAILED OPENS BEFORE UNLOCK 2") || !sessionStats->text().contains("KEYS 1") || activityWelcome->toPlainText()!=preferences.value("activity_welcome").toString()) {fail("Theme or Qubes broker setting failed"); return;}
                rpcProbe({{"version",1},{"operation","sign"},{"caller","deny-test"},{"fingerprint",testFingerprint},{"text","deny fixture"}},false,[this,after] {
                    rpcProbe({{"version",1},{"operation","sign"},{"caller","work-mail"},{"fingerprint",testFingerprint},{"text","local broker signing fixture"}},true,[this,after] {
                        rpcProbe({{"version",1},{"operation","sign"},{"caller","dom0"},{"fingerprint",testFingerprint},{"text","spoof fixture"}},false,[this,after] {
                            preferences.insert("qubes_rpc",false); preferences.insert("theme","solarized"); applyPreferences(preferences);
                            if(rpcServer.isListening() || qApp->palette().color(QPalette::Window)!=QColor("#002b36")) {fail("RPC disable or Solarized theme failed"); return;}
                            after();
                        });
                    });
                });
            });
        });
    }

    void testWaitForUi(std::function<void()> after,int attempt=0) {
        if(attempt>=400) {fail("Protection UI operation timed out"); return;}
        if(!pending) {after(); return;}
        QTimer::singleShot(50,this,[this,after,attempt] {testWaitForUi(after,attempt+1);});
    }

    void testProtectionControls(std::function<void()> after) {
        // Drive the same checkbox and modal dialog paths as a user, using only
        // the disposable self-test vault under isolated HOME.
        refreshProtectionStatus(); testWaitForUi([this,after] {
            if(protectionMaster || protectionOptionChecks.size()!=3 || protectionOptionControls[0]->isEnabled()) {fail("New vault protection controls were active"); return;}
            QTimer::singleShot(0,this,[this] {auto* warning=qobject_cast<QMessageBox*>(QApplication::activeModalWidget()); if(!warning) {fail("Master protection warning missing"); return;} warning->button(QMessageBox::Yes)->click();});
            protectionMasterCheck->setChecked(true);
            testWaitForUi([this,after] {
                if(!protectionMaster || protectionOptionChecks[0]->isChecked() || protectionOptionControls[0]->isEnabled()) {fail("Master enable restored an option"); return;}
                protectionOptionChecks[0]->setChecked(true);
                testWaitForUi([this,after] {
                    if(!protectionOptionControls[0]->isEnabled()) {fail("Dummy checkbox did not permit setup"); return;}
                    QTimer::singleShot(0,this,[this] {
                        auto* dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
                        auto* pass=dialog?dialog->findChild<QLineEdit*>("alternativePassword"):nullptr; auto* confirm=dialog?dialog->findChild<QLineEdit*>("alternativeConfirmation"):nullptr;
                        if(!pass || !confirm || !pass->text().isEmpty() || !confirm->text().isEmpty() || pass->echoMode()!=QLineEdit::Password) {fail("Alternative password dialog leaked setup or was missing"); if(dialog) dialog->reject(); return;}
                        pass->setText("d"); confirm->setText("d"); auto* buttons=dialog->findChild<QDialogButtonBox*>(); if(!buttons || !buttons->button(QDialogButtonBox::Save)->isEnabled()) {fail("Short alternative password was blocked"); dialog->reject(); return;} buttons->button(QDialogButtonBox::Save)->click();
                    });
                    dummyPasswordDialog();
                    testWaitForUi([this,after] {
                        request("dummy_status",{},[this,after](bool ok,const QJsonObject& status) {
                            if(!ok || !status.value("armed").toBool()) {fail("Dummy dialog did not save a working verifier"); return;}
                            request("document_save",{{"title","Protection UI fixture"},{"text","Disposable saved text"}},[this,after](bool saved,const QJsonObject&) {
                                if(!saved) return;
                                request("dummy_status",{},[this,after](bool checked,const QJsonObject& rebound) {
                                    if(!checked || !rebound.value("armed").toBool()) {fail("Normal vault save disarmed the dummy password"); return;}
                                    protectionOptionChecks[0]->setChecked(false);
                                    testWaitForUi([this,after] {
                                        if(QFileInfo::exists(activeVaultPath+".pgpcrypt-dummy") || protectionOptionControls[0]->isEnabled()) {fail("Disabling dummy did not erase its configuration"); return;}
                                        protectionOptionChecks[0]->setChecked(true);
                                        testWaitForUi([this,after] {
                                            if(QFileInfo::exists(activeVaultPath+".pgpcrypt-dummy")) {fail("Re-enabling dummy restored its old verifier"); return;}
                                            protectionMasterCheck->setChecked(false);
                                            testWaitForUi([this,after] {
                                                if(protectionMaster || protectionOptionChecks[0]->isChecked() || QFileInfo::exists(activeVaultPath+".pgpcrypt-dummy")) {fail("Master disable did not clear option controls"); return;}
                                                after();
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    }

    bool testRecentVaultHistory() {
        if(!recentVaultStore.available || !recentVaultStore.enabled || !recentVaultStore.paths.isEmpty() || !recentVaultStore.directory.startsWith(QDir::homePath()+"/")) {fail("Recent-vault test state is not isolated"); return false;}
        const auto fixture=QDir::home().filePath("recent-vault-fixture.age"); recentVaultStore.remember(fixture); updateRecentVaultUi();
        if(recentVaultList->count()!=1) {fail("Recent vault did not appear on landing page"); return false;}
        openRecentVault(recentVaultList->item(0));
        if(root->currentWidget()!=lockedPage || creatingVault || path->text()!=fixture || !password->text().isEmpty()) {fail("Recent vault did not lead to password entry"); return false;}
        RecentVaultStore reopened(true);
        if(!reopened.enabled || reopened.paths!=QStringList{fixture}) {fail("Recent-vault paths did not persist"); return false;}
        struct stat metadata{}; const auto state=QFile::encodeName(recentVaultStore.directory+"/recent-vaults.json");
        if(::lstat(state.constData(),&metadata)!=0 || !RecentVaultStore::privateFile(metadata)) {fail("Recent-vault state is not private"); return false;}
        rememberVaultsCheck->setChecked(false); RecentVaultStore disabled(true);
        if(disabled.enabled || !disabled.paths.isEmpty() || recentVaultList->count()!=0) {fail("Disabling recent vaults did not clear saved paths"); return false;}
        rememberVaultsCheck->setChecked(true); RecentVaultStore enabled(true);
        if(!enabled.enabled || !enabled.paths.isEmpty()) {fail("Re-enabling recent vaults restored cleared paths"); return false;}
        clearVaultCredentials(); path->clear(); root->setCurrentWidget(homePage); return true;
    }

    void testCreate() {
        // Actual wrong-password opens must be counted before the successful
        // unlock/create which makes encrypted counter preferences available.
        const auto filename=QDir::home().filePath("counter-fixture.age"); QProcess fixture; fixture.setProgram(QCoreApplication::applicationDirPath()+"/pgpcrypt-worker"); fixture.start();
        if(!fixture.waitForStarted(5000)) {fail("Counter fixture worker could not start"); return;}
        auto bytes=QJsonDocument(QJsonObject{{"id",1},{"op","create"},{"path",filename},{"password","counter fixture secret"}}).toJson(QJsonDocument::Compact); bytes.append('\n'); fixture.write(bytes); bytes.fill('\0'); fixture.closeWriteChannel();
        if(!fixture.waitForFinished(20000) || !QJsonDocument::fromJson(fixture.readAllStandardOutput()).object().value("ok").toBool()) {fail("Counter fixture vault could not be created"); return;}
        expectedTestError=true;
        request("open",{{"path",filename},{"password","wrong first"}},[this,filename](bool ok,const QJsonObject&) {
            if(ok) {expectedTestError=false; fail("Wrong counter-fixture password was accepted"); return;}
            request("open",{{"path",filename},{"password","wrong second"}},[this](bool ok,const QJsonObject&) {
                expectedTestError=false; if(ok || failedOpens!=2) {fail("Failed unlocks were not counted in this window"); return;}
                testCreateForm();
            });
        });
    }

    void testCreateForm() {
        if(!testRecentVaultHistory()) return;
        if(root->currentWidget()!=homePage) { fail("Start screen is missing"); return; }
        showVaultForm(true);
        if(path->text()!=QDir::home().filePath("vault.pgpcrypt.age") || !confirmation->isVisible()) { fail("Create form defaults are missing"); return; }
        if(testKdbx) {
            formatChoice->setCurrentIndex(1);
            if(path->text()!=QDir::home().filePath("vault.kdbx")) { fail("KDBX filename default did not follow format choice"); return; }
        }
        password->setText("passwordpassword"); updatePasswordStrength();
        if(strengthMeter->value()>1 || unlockButton->isEnabled()) { fail("Weak-password estimate or confirmation requirement failed"); return; }
        password->setText("7q!P2@vz#R9fW4$xD0+K5"); updatePasswordStrength();
        if(strengthMeter->value()<3) { fail("Strong-password estimate failed"); return; }
        confirmation->setText("mismatch");
        if(unlockButton->isEnabled()) { fail("Mismatched confirmation was accepted"); return; }
        // The self-test HOME is isolated in main. A relative filename must work
        // even when the installed application starts in a read-only directory.
        path->setText(testKdbx?"vault.kdbx":"vault.pgpcrypt.age");
        password->setText("disposable Qt fixture passphrase"); confirmation->setText(password->text());
        unlockButton->click();
    }
    void testGenerate() {
        if(recentVaultStore.paths.isEmpty() || recentVaultStore.paths.first()!=activeVaultPath || recentVaultList->count()!=1) {fail("Successful vault creation was not remembered"); return;}
        const QFileInfo created(QDir::home().filePath(testKdbx?"vault.kdbx":"vault.pgpcrypt.age"));
        if(currentFormat!=(testKdbx?"kdbx":"age")) { fail("Created vault format differs from selection"); return; }
        if(!created.isFile() || created.ownerId()!=static_cast<uint>(geteuid())
            || (created.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ReadOther | QFileDevice::WriteOther))) {
            fail("Default vault was not created privately in the current user's home"); return;
        }
        QJsonObject options{{"name","Desktop fixture"},{"email","fixture@example.invalid"},{"algorithm","cv25519"},{"layout","subkeys"},{"signing",true},{"certification",true},{"transport_encryption",true},{"storage_encryption",true},{"expires_at",QJsonValue(QJsonValue::Null)}};
        request("generate",{{"key_options",options},{"password",testKdbx?"":"x"}},[this](bool ok,const QJsonObject&) {
            if(!ok) return;
            refreshKeys([this] {
                if(keys->rowCount()!=1) { fail("Key table did not populate"); return; }
                keys->selectRow(0);
                testFingerprint=keys->item(0,2)->text();
                if(recipientChoices->count()!=1 || signingChoice->findData(testFingerprint)<1) { fail("Notepad key choices did not populate"); return; }
                recipientChoices->item(0)->setCheckState(Qt::Checked); signingChoice->setCurrentIndex(signingChoice->findData(testFingerprint));
                request("settings_set",{{"default_signing_key",testFingerprint}},[this](bool ok,const QJsonObject&) {
                    if(!ok) return;
                    signingChoice->setCurrentIndex(0);
                    refreshKeys([this] {
                        if(defaultSigner!=testFingerprint || signer!=testFingerprint || recipientChoices->item(0)->checkState()!=Qt::Checked) { fail("Notepad default or recipients were not restored"); return; }
                        if(!notepadPage->isAncestorOf(signingChoice) || !notepadPage->isAncestorOf(recipientChoices)) { fail("Key controls are outside the notepad"); return; }
                        performCrypto("private_export",{{"fingerprint",testFingerprint}},[this](bool exported,const QJsonObject& privateKey) {
                            if(!exported || !privateKey.value("text").toString().startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----") || privateKey.value("protected").toBool()==testKdbx) {fail("Authenticated private export failed"); return;}
                            testClipboardImport([this] {testSettingsAndQubes([this] {testProtectionControls([this] {testProfilesAndDocuments([this] {testNotepadWorkflow();});});});});
                        });
                    });
                });
            });
        });
    }
    void testProfilesAndDocuments(std::function<void()> after) {
        request("profile_save",{{"profile_name","Desktop identity"},{"profile_fingerprints",QJsonArray{testFingerprint}}},[this,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            const auto included=data.value("id").toString();
            request("profile_save",{{"profile_name","Empty category"},{"profile_fingerprints",QJsonArray{}}},[this,after,included](bool ok,const QJsonObject& data) {
                if(!ok) return;
                const auto empty=data.value("id").toString();
                refreshKeys([this,after,included,empty] {
                    selectProfile(empty);
                    if(keys->rowCount()!=0 || recipientChoices->count()!=0 || !signer.isEmpty()) {fail("Empty profile leaked key choices"); return;}
                    selectProfile(included);
                    if(identityOverview->rowCount()!=2 || !notepadProfileTabs || notepadProfileTabs->count()!=profileTabs->count() || notepadProfileTabs->tabData(notepadProfileTabs->currentIndex()).toString()!=included) {fail("Identity overview or mirrored profiles did not update"); return;}
                    if(keys->rowCount()!=1 || recipientChoices->count()!=1 || signer!=testFingerprint || profileTabs->count()!=4) {fail("Profile did not filter both pages"); return;}
                    notepadProfileTabs->setCurrentIndex(profileTabIndex(empty));
                    if(activeProfile!=empty || profileTabs->currentIndex()!=profileTabIndex(empty)) {fail("Notepad profile changes did not reach the main window"); return;}
                    selectProfile(included); profileSelector->setCurrentIndex(profileSelector->findData(included));
                    const auto savedName=profileName->text(); profileName->setText("Unsaved identity draft"); populateProfileManager();
                    if(profileName->text()!="Unsaved identity draft" || !identityDirty) {fail("Workspace refresh discarded an identity draft"); return;}
                    profileName->setText(savedName); identityDirty=false; populateProfileManager();
                    recipientChoices->item(0)->setCheckState(Qt::Checked);
                    request("document_save",{{"title","Vault document fixture"},{"text","Saved only inside the vault"},{"profile_id",included}},[this,after,included](bool ok,const QJsonObject&) {
                        if(!ok) return;
                        refreshDocuments([this,after,included] {
                            if(documents->rowCount()!=1 || recentDocuments->rowCount()!=1 || notepadPage->isAncestorOf(documents) || !tabs->widget(3)->isAncestorOf(documents) || recentDocuments->item(0,0)->data(Qt::UserRole)!=documents->item(0,0)->data(Qt::UserRole) || profileDocumentCounts.value(included).toInteger()!=1) {fail("Vault document browser or identity counts did not populate"); return;}
                            documents->selectRow(0); const auto id=documents->item(0,0)->data(Qt::UserRole).toString();
                            request("document_get",{{"document_id",id},{"profile_id",included}},[this,after,id](bool ok,const QJsonObject& data) {
                                if(!ok || data.value("text").toString()!="Saved only inside the vault") {fail("Saved document did not reopen"); return;}
                                currentDocumentId=id; currentDocumentTitle=data.value("title").toString(); currentDocumentProfile=data.value("profile_id").toString(); input->setPlainText(data.value("text").toString()); updateDocumentContext();
                                if(!documentContext->text().contains("Vault document fixture")) {fail("Opened document context is missing"); return;}
                                after();
                            });
                        });
                    });
                });
            });
        });
    }

    void testNotepadWorkflow() {
        tabs->setCurrentIndex(1); input->setPlainText("Qt desktop private fixture");
        textAction("encrypt",[this] {
            textAction("decrypt",[this] {
                if(output->toPlainText()!="Qt desktop private fixture") {fail("Decryption mismatch"); return;}
                input->setPlainText("Qt signature fixture");
                textAction("sign",[this] {
                    const auto signedText=output->toPlainText();
                    if(!signedText.startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) {fail("Sign did not produce readable signed text"); return;}
                    textAction("verify",[this,signedText] {
                        auto* comparison=verificationPopup?verificationPopup->findChild<QTableWidget*>("verificationComparison"):nullptr;
                        if(output->toPlainText()!="Qt signature fixture" || !verificationIdentity->text().contains("Desktop fixture") || !verificationIdentity->text().contains(testFingerprint) || !statusBar()->currentMessage().contains("Desktop fixture") || !statusBar()->currentMessage().contains(testFingerprint) || !copyOutput->isEnabled() || !verificationPopup || !verificationPopup->property("verificationPassed").toBool() || !comparison || comparison->item(0,2)->text()!=testFingerprint || comparison->item(1,2)->text()!=testFingerprint) {fail("Verification popup or identity comparison mismatch"); return;}
                        auto altered=signedText; altered.replace("Qt signature fixture","Qt altered fixture"); input->setPlainText(altered);
                        textAction("verify",[this,signedText] {
                            if(!verificationPopup || verificationPopup->property("verificationPassed").toBool() || verificationPopup->findChild<QTableWidget*>("verificationComparison") || !output->toPlainText().isEmpty() || !statusBar()->currentMessage().contains("FAILED") || verificationIdentity->text().contains(testFingerprint)) {fail("Invalid signature retained successful verification state"); return;}
                            input->setPlainText(signedText); textAction("verify",[this] {testReusableWorkflows();});
                        });
                    },true);
                });
            },true);
        });
    }

    void testReusableWorkflows() {
        input->setPlainText("Qt signature fixture"); workflowChoice->setCurrentIndex(0);
        runWorkflow(false,[this] {
            if(workflowRunning || !tabs->isEnabled() || input->toPlainText()!="Qt signature fixture" || !output->toPlainText().startsWith("-----BEGIN PGP MESSAGE-----")) {fail("Sign/encrypt workflow failed or changed Input"); return;}
            workflowChoice->setCurrentIndex(1);
            runWorkflow(true,[this] {
                if(workflowRunning || output->toPlainText()!="Qt signature fixture" || !outputHasProof() || !verificationPopup || !verificationPopup->property("verificationPassed").toBool()) {fail("Decrypt/verify workflow failed"); return;}
                // A repeated Verify on authenticated plaintext uses its existing
                // proof. Changing Output must invalidate that proof immediately.
                textAction("verify",[this] {
                    if(!verificationPopup || !verificationPopup->property("verificationPassed").toBool()) {fail("Verify output lost its authenticated proof"); return;}
                    output->setPlainText("Tampered literal fixture");
                    if(outputHasProof()) {fail("Changed Output retained an authenticated proof"); return;}
                    textAction("verify",[this] {
                        if(!verificationPopup || verificationPopup->property("verificationPassed").toBool() || verificationIdentity->text().contains(testFingerprint)) {fail("Changed Output retained a verification success"); return;}
                        workflowChoice->addItem("Stop fixture",QJsonObject{{"name","Stop fixture"},{"steps",QJsonArray{"verify","encrypt"}}}); workflowChoice->setCurrentIndex(workflowChoice->count()-1); input->setPlainText("Not a signed message");
                        runWorkflow(false,[this] {
                            if(workflowRunning || !tabs->isEnabled() || !output->toPlainText().isEmpty()) {fail("Failed workflow did not stop without publishing an intermediate result"); return;}
                            // Resume a valid result for the existing save/lock checks.
                            input->setPlainText("Qt signature fixture"); textAction("sign",[this] {textAction("verify",[this] {testAutomationBatch([this]{testSavedMessageAndFinish();});},true);});
                        });
                    },true);
                },true);
            });
        });
    }

    void testAutomationBatch(std::function<void()> after) {
        const auto pane=findChild<QSplitter*>("notepadPanes");if(!pane||pane->orientation()!=Qt::Horizontal||!workflowEditor){fail("Automation page or side-by-side Notepad is missing");return;}
        for(const auto& source:QStringList{"Input","Output"})for(const auto& op:QStringList{"sign","verify","encrypt","decrypt"})if(!findChild<QPushButton*>(op+source)){fail("A Notepad panel operation is missing");return;}
        const auto folder=QDir::home().filePath("batch-fixtures");QDir().mkpath(folder);
        auto write=[](const QString& path,const QByteArray& text){QFile file(path);return file.open(QIODevice::WriteOnly)&&file.write(text)==text.size();};
        const auto first=folder+"/first.txt",second=folder+"/second.txt",bad=folder+"/bad.txt",existing=folder+"/existing.txt",link=folder+"/link.txt";
        if(!write(first,"Batch first fixture")||!write(second,"Batch second fixture")||!write(bad,QByteArray("bad\0data",8))||!write(existing,"preserve existing")){fail("Could not create batch fixtures");return;}
        if(AutomationFiles::writeNew(existing,"replace",true).committed||AutomationFiles::safeName("../escape")||AutomationFiles::expand("{unknown}",first,1,"x").size()!=0){fail("Batch output preflight permitted an unsafe name or overwrite");return;}
        if(::symlink(QFile::encodeName(existing).constData(),QFile::encodeName(link).constData())!=0){fail("Could not create symbolic-link fixture");return;}if(AutomationFiles::writeNew(link,"replace",true).committed){fail("Batch output followed a symbolic link");return;}
        QJsonArray steps;for(const auto& op:QStringList{"sign","encrypt","decrypt","verify"})steps.append(QJsonObject{{"operation",op},{"selection","keys"},{"fingerprints",QJsonArray{testFingerprint}},{"require_all_signers",op=="verify"}});
        const QJsonObject preset{{"name","Batch fixture"},{"steps",steps},{"output_pattern","{stem}-{index}.txt"}};const auto oldInput=input->toPlainText(),oldOutput=output->toPlainText();
        startBatch(preset,messageContext(),QList<BatchJob>{{first,folder+"/first.out"},{bad,folder+"/bad.out"},{second,folder+"/second.out"}},true,[this,after,folder,oldInput,oldOutput]{
            QString a,b;const auto e1=AutomationFiles::read(folder+"/first.out",true,&a),e2=AutomationFiles::read(folder+"/second.out",true,&b);int complete=0,failed=0;for(const auto& window:jobWindows)if(window){auto* body=window->findChild<QPlainTextEdit*>();if(window->windowTitle().contains(" completed "))++complete;else{++failed;if(body&&!body->toPlainText().isEmpty()){fail("Failed batch job published plaintext");return;}}}
            if(activeBatch||workflowRunning||!e1.isEmpty()||!e2.isEmpty()||a!="Batch first fixture"||b!="Batch second fixture"||QFileInfo::exists(folder+"/bad.out")||complete!=2||failed!=1||input->toPlainText()!=oldInput||output->toPlainText()!=oldOutput){fail("Batch jobs lost independent results, failed to continue or changed Notepad");return;}
            if(QFileInfo(folder+"/first.out").permissions()&(QFileDevice::ReadGroup|QFileDevice::WriteGroup|QFileDevice::ReadOther|QFileDevice::WriteOther)){fail("Batch output permissions are not private");return;}
            for(auto& window:jobWindows) {if(window)window->close();}
            QTimer::singleShot(0,this,after);
        });
    }

    void testSavedMessageAndFinish() {
        if(output->toPlainText()!="Qt signature fixture") {fail("Valid signature did not recover after failure"); return;}
        copyOutput->click(); input->setPlainText("This previous Input must be replaced"); pasteInput->click();
        if(input->toPlainText()!=output->toPlainText()) {fail("Copy all and Paste did not preserve output"); return;}
        const auto fixture=QDir::home().filePath("saved-message.txt");
        if(!saveOutputFile(fixture) || !loadMessageFile(fixture) || input->toPlainText()!="Qt signature fixture" || !currentDocumentId.isEmpty() || !verificationIdentity->text().isEmpty() || (verificationPopup && verificationPopup->isVisible())) {fail("Message save/load did not preserve text or clear verification"); return;}
        const QFileInfo saved(fixture);
        if(saved.permissions() & (QFileDevice::ReadGroup|QFileDevice::WriteGroup|QFileDevice::ReadOther|QFileDevice::WriteOther)) {fail("Saved message is not private"); return;}
        request("notes_set",{{"text","encrypted Qt note"}},[this](bool ok,const QJsonObject&) {
            if(!ok) return;
            request("notes_get",{},[this](bool ok,const QJsonObject& data) {
                if(!ok || data.value("text").toString()!="encrypted Qt note") {fail("Notes mismatch"); return;}
                if(!screenshotPath.isEmpty()) {auto value=preferences; value.insert("notepad_popout",false); applyPreferences(value);}
                tabs->setCurrentIndex(screenshotPath.isEmpty()?0:1);
                QTimer::singleShot(100,this,[this] {
                    if(!screenshotPath.isEmpty() && !(notepadPopout && notepadWindow && notepadWindow->isVisible()?notepadWindow->grab():grab()).save(screenshotPath)) {fail("Screenshot failed"); return;}
                    copySessionText("disposable lock clipboard fixture"); endSession(true);
                });
            });
        });
    }

};
}

int main(int argc,char** argv) {
    bool child=false,selfTest=false,smoke=false,restartProbe=false,kdbxProbe=false;
    QString screenshot;
    for(int i=1;i<argc;++i) {
        const QByteArray argument(argv[i]);
        if(argument=="--session") child=true;
        if(argument=="--self-test") selfTest=child=true;
        if(argument=="--self-test-kdbx") selfTest=child=kdbxProbe=true;
        if(argument=="--smoke-ui") smoke=child=true;
        if(argument=="--test-lock-restart") restartProbe=true;
        if(argument=="--screenshot" && i+1<argc) screenshot=QString::fromLocal8Bit(argv[++i]);
    }
    // Only session children depend on the supervisor's lifetime. Desktop
    // launchers may exit immediately after starting the top-level supervisor.
    if(!harden(child)) { std::fputs("Could not apply process hardening\n",stderr); return 1; }
    std::unique_ptr<QTemporaryDir> fixtureHome;
    if(selfTest || smoke || restartProbe) {
        fixtureHome=std::make_unique<QTemporaryDir>(QDir::tempPath()+"/pgpcrypt-ui-home-XXXXXX");
        if(!fixtureHome->isValid()) { std::fputs("Cannot create isolated test home\n",stderr); return 1; }
        qputenv("HOME",QFile::encodeName(fixtureHome->path()));
        qputenv("XDG_STATE_HOME",QFile::encodeName(fixtureHome->path()+"/.local/state"));
    }
    if(!child) {
        // The supervisor never receives a vault path, password, or decrypted data.
        QCoreApplication app(argc,argv); QProcess session;
        session.setStandardOutputFile(QProcess::nullDevice());
        session.setStandardErrorFile(QProcess::nullDevice());
        int restarts=0; qint64 firstPid=0,secondPid=0;
        auto start=[&] {
            QStringList arguments{"--session"};
            if(restartProbe) {
                if(restarts==0) arguments.append({"--self-test","--test-lock-restart"});
                else arguments.append("--smoke-ui");
            }
            session.start(QCoreApplication::applicationFilePath(),arguments);
        };
        QObject::connect(&session,&QProcess::started,&app,[&] {
            if(restarts==0) firstPid=session.processId(); else secondPid=session.processId();
        });
        QObject::connect(&session,&QProcess::finished,&app,[&](int code,QProcess::ExitStatus status) {
            if(status==QProcess::NormalExit && code==RestartLocked) { ++restarts; QTimer::singleShot(0,&app,start); }
            else if(restartProbe) {
                const bool passed=status==QProcess::NormalExit && code==0 && restarts==1 && firstPid!=secondPid && secondPid>0;
                std::fputs(passed?"Supervisor test passed: lock replaced the session process\n":"Supervisor test FAILED\n",passed?stdout:stderr);
                app.exit(passed?0:1);
            } else app.exit(status==QProcess::NormalExit?code:1);
        });
        QObject::connect(&session,&QProcess::errorOccurred,&app,[&](QProcess::ProcessError error) { if(error==QProcess::FailedToStart) app.exit(1); });
        start(); return app.exec();
    }
    // QFileDialog writes history to QtProject.conf even in widget mode.
    // Point per-user QSettings at a non-directory so those writes cannot create
    // plaintext vault-path history. This applies to this process only.
    QSettings::setPath(QSettings::NativeFormat,QSettings::UserScope,"/dev/null");
    QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,"/dev/null");
    QApplication app(argc,argv);
    app.setApplicationName("PGPCrypt"); app.setQuitOnLastWindowClosed(true);
    Window window(selfTest,screenshot,restartProbe,kdbxProbe); window.show();
    if(smoke) window.smoke();
    if(selfTest) QTimer::singleShot(60000,&app,[&]{ std::fputs("Qt desktop self-test timed out\n",stderr); app.exit(1); });
    return app.exec();
}

#include "main.moc"
