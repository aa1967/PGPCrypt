#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QComboBox>
#include <QDateTimeEdit>
#include <QDialog>
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
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSet>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QSettings>
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
#include <functional>
#include <memory>
#include <cstdio>
#include <csignal>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <zxcvbn.h>

namespace {
constexpr int RestartLocked = 75;
constexpr qsizetype MaxFrame = 8 * 1024 * 1024;
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

class Window final : public QMainWindow {
    Q_OBJECT
public:
    explicit Window(bool selfTest, const QString& screenshot, bool restartProbe = false, bool kdbxProbe = false)
        : testing(selfTest), restartTest(restartProbe), testKdbx(kdbxProbe), screenshotPath(screenshot) {
        setWindowTitle("PGPCrypt");
        resize(1160, 820);
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.setReadChannel(QProcess::StandardOutput);
        connect(&process, &QProcess::readyReadStandardOutput, this, [this] { receive(); });
        connect(&process, &QProcess::readyReadStandardError, this, [this] { process.readAllStandardError().fill('\0'); });
        connect(&process, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
            if (!ending) { fail("The crypto worker stopped. This session will close."); endSession(false); }
        });

        root = new QStackedWidget;
        setCentralWidget(root);
        buildLocked();
        buildSession();
        auto* vaultMenu = menuBar()->addMenu("&Vault");
        lockAction = vaultMenu->addAction("&Lock vault", QKeySequence("Ctrl+L"), this, [this] { endSession(true); });
        lockAction->setEnabled(false);
        vaultMenu->addAction("&Quit", QKeySequence::Quit, this, &QWidget::close);
        auto* settingsMenu=menuBar()->addMenu("&Settings");
        settingsAction=settingsMenu->addAction("Preferences…",this,[this] { settingsDialog(); }); settingsAction->setEnabled(false);
        convertAction=settingsMenu->addAction("Save converted vault copy…",this,[this] { convertVault(); }); convertAction->setEnabled(false);
        wireClipboard();
        connect(&rpcServer,&QLocalServer::newConnection,this,[this] { acceptQubes(); });
        auto* help = menuBar()->addMenu("&Help");
        help->addAction("Security boundaries", this, [this] {
            QMessageBox::information(this, "Security boundaries", "Experimental software. Vault contents are encrypted while locked. "
                "Qt text, clipboard managers, swap, and the desktop can retain plaintext. Lock terminates this UI and its crypto worker; "
                "it cannot retract external copies. Public exports and message signatures can reveal identities.");
        });
        statusBar()->showMessage("Offline • No system keyring • Experimental version");
        idle.start();
        connect(&idle, &QTimer::timeout, this, [this] {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            if (unlocked && autoLock && (activityClock.elapsed() >= idleTimeoutSeconds * 1000LL || now - lastTick > 15000 || now < lastTick)) endSession(true);
            lastTick = now;
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
    bool unlocked = false, ending = false, testing = false, restartTest = false, creatingVault = false, testKdbx = false;
    QString screenshotPath;
    QTimer idle;
    QTimer strengthTimer;
    QElapsedTimer activityClock;
    int idleTimeoutSeconds = 300, clipboardSeconds = 0;
    bool autoLock = false, focusLock = false, sessionLock = false, qubesEnabled = false;
    QJsonObject preferences;
    QTimer clipboardTimer, selectionTimer;
    QAction *settingsAction = nullptr, *convertAction = nullptr;
    qint64 lastTick = 0;
    QStackedWidget *root = nullptr;
    QWidget *sessionPage = nullptr, *lockedPage = nullptr, *homePage = nullptr;
    QLineEdit *path = nullptr, *password = nullptr, *confirmation = nullptr, *search = nullptr;
    QLabel *vaultTitle = nullptr, *confirmationLabel = nullptr, *strengthLabel = nullptr, *passwordHint = nullptr, *matchStatus = nullptr;
    QProgressBar* strengthMeter = nullptr;
    QComboBox* formatChoice = nullptr;
    QLabel* formatLabel = nullptr;
    QString currentFormat = "age";
    QLabel* sessionWarning = nullptr;
    QPushButton* unlockButton = nullptr;
    QLabel *lockedStatus = nullptr, *details = nullptr, *selectionSummary = nullptr;
    QTableWidget* keys = nullptr;
    QTabWidget* tabs = nullptr;
    QPlainTextEdit *importText = nullptr, *input = nullptr, *output = nullptr;
    QAction* lockAction = nullptr;
    QString signer, defaultSigner;
    QListWidget* recipientChoices = nullptr;
    QComboBox* signingChoice = nullptr;
    QLabel* defaultKeyLabel = nullptr;
    QString testFingerprint;
    bool outputIsEncrypted = false;
    QLocalServer rpcServer;
    bool rpcBusy=false;
    QElapsedTimer rpcRate;
    int rpcConnections=0;
    QString rpcPath;

    void fail(const QString& message) {
        statusBar()->showMessage(message);
        lockedStatus->setText(message);
        if (testing) { std::fputs("Qt desktop self-test FAILED\n", stderr); ending = true; process.kill(); process.waitForFinished(5000); qApp->exit(1); }
    }

    void request(const QString& operation, QJsonObject fields, Reply callback) {
        if (pending || ending) { fail("Another operation is in progress"); return; }
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
        pendingId = sequence;
        pending = std::move(callback);
        tabs->setEnabled(false);
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
        tabs->setEnabled(true); lockedPage->setEnabled(true);
        const bool ok = response.value("ok").toBool();
        const auto code=response.value("code").toString();
        if(!ok && code=="vault_reopen_required") {
            const QString message="The vault was saved, but its folder could not be synced. Reopen it before making more changes. Keep a backup before shutting down.";
            if(testing) {fail(message); return;}
            endSession(true,message); return;
        }
        if (!ok && code!="password_required") fail(response.value("error").toString("Operation failed"));
        else statusBar()->showMessage("Ready • Offline");
        auto data=response.value("data").toObject(); if(!ok) data.insert("_error_code",code);
        if (callback) callback(ok,data);
        updateVaultSubmit();
    }

    void endSession(bool restart, const QString& notice = {}) {
        if (ending) return;
        ending = true;
        idle.stop(); rpcServer.close(); if(!rpcPath.isEmpty()) {QLocalServer::removeServer(rpcPath); rpcPath.clear();}
        if(clipboardSeconds>0) { if(qApp->clipboard()->ownsClipboard()) qApp->clipboard()->clear(); if(qApp->clipboard()->ownsSelection()) qApp->clipboard()->clear(QClipboard::Selection); }
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
        welcome->addWidget(new QLabel("Offline key management • age and KeePass vaults"));
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
        passwordHint = new QLabel("Use at least 16 characters. Prefer randomly generated words or a password manager. There is no password reset.");
        passwordHint->setWordWrap(true); outer->addWidget(passwordHint);
        matchStatus = new QLabel; matchStatus->setTextFormat(Qt::PlainText); outer->addWidget(matchStatus);
        strengthTimer.setSingleShot(true); strengthTimer.setInterval(180);
        connect(&strengthTimer,&QTimer::timeout,this,[this] { updatePasswordStrength(); });
        connect(password,&QLineEdit::textChanged,this,[this] {
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
            if(creatingVault && (password->text().toUcs4().size()<16 || password->text()!=confirmation->text())) { fail("Use at least 16 characters and matching passwords/passphrases"); return; }
            const auto filename = absoluteVaultPath(path->text());
            if(filename.isEmpty()) { fail("Choose a vault file"); return; }
            path->setText(filename); lockedStatus->clear();
            QJsonObject fields{{"path",filename},{"password",password->text()}};
            if(creatingVault) fields.insert("format",formatChoice->currentData().toString());
            const auto op = creatingVault ? "create" : "open";
            clearVaultCredentials();
            request(op,fields,[this](bool ok,const QJsonObject& data) {
                if (!ok) return;
                unlocked = true; lockAction->setEnabled(true); root->setCurrentWidget(sessionPage);
                currentFormat=data.value("format").toString("age");
                settingsAction->setEnabled(true); convertAction->setEnabled(true);
                idleTimeoutSeconds=data.value("idle_timeout_seconds").toInt(300); applyPreferences(data.value("preferences").toObject());
                path->clear(); lockedStatus->clear();
                activityClock.restart();
                refreshKeys([this] { if (testing) testGenerate(); });
            });
        });
        lockedStatus = new QLabel; lockedStatus->setTextFormat(Qt::PlainText); lockedStatus->setWordWrap(true); outer->addWidget(lockedStatus);
        outer->addStretch();
        auto* warning = new QLabel("Alpha version • Keep backups. Vault filename and size remain visible while locked.");
        warning->setWordWrap(true); outer->addWidget(warning);
        root->addWidget(lockedPage);
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
        unlockButton->setEnabled(!pending && !ending && !path->text().isEmpty() && !password->text().isEmpty()
            && (!creatingVault || (password->text().toUcs4().size()>=16 && matches)));
        if(matchStatus) matchStatus->setText(creatingVault && !confirmation->text().isEmpty() && !matches?"Passwords/passphrases do not match.":QString());
    }

    void updatePasswordStrength() {
        if(!creatingVault || password->text().isEmpty()) return;
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
        auto* info=new QLabel("Copy PGPCrypt keys and settings to a new vault. The original stays open and unchanged. Other KeePass entries stay in the original.");
        info->setWordWrap(true); layout->addWidget(info);
        auto* format=new QComboBox; format->addItem("age v1","age"); format->addItem("KeePass KDBX 4.1 (alpha support)","kdbx"); format->setCurrentIndex(currentFormat=="age"?1:0); form->addRow("Destination format",format);
        auto* filename=new QLineEdit; auto* row=new QHBoxLayout; auto* browse=new QPushButton("Browse…"); row->addWidget(filename); row->addWidget(browse); form->addRow("New vault file",row);
        auto* pass=new QLineEdit; pass->setEchoMode(QLineEdit::Password); pass->setMaxLength(256); pass->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText);
        auto* confirm=new QLineEdit; confirm->setEchoMode(QLineEdit::Password); confirm->setMaxLength(256); confirm->setInputMethodHints(pass->inputMethodHints());
        form->addRow("New password/passphrase",pass); form->addRow("Confirm password/passphrase",confirm); layout->addLayout(form);
        auto* strength=new QLabel("Use at least 16 characters and matching passwords/passphrases."); strength->setTextFormat(Qt::PlainText); layout->addWidget(strength);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); layout->addWidget(buttons);
        auto update=[=] {
            buttons->button(QDialogButtonBox::Save)->setEnabled(!filename->text().isEmpty() && pass->text().toUcs4().size()>=16 && pass->text()==confirm->text());
            auto bytes=pass->text().toUtf8(); const double entropy=ZxcvbnMatch(bytes.constData(),nullptr,nullptr); bytes.fill('\0');
            const QStringList levels{"Very weak","Weak","Fair","Good","Strong"}; int score=entropy<10?0:entropy<20?1:entropy<26.575?2:entropy<33.22?3:4;
            strength->setText("Estimated strength: "+levels[score]+" • Minimum 16 characters; confirmation required.");
        };
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
        auto* title = new QLabel("Private key workspace"); title->setStyleSheet("font-size: 22px; font-weight: 600;");
        heading->addWidget(title); heading->addStretch();
        auto* lock = new QPushButton("Lock vault  Ctrl+L"); heading->addWidget(lock);
        connect(lock,&QPushButton::clicked,this,[this] { endSession(true); });
        layout->addLayout(heading);
        auto* split = new QSplitter;
        auto* navigation = new QListWidget; navigation->addItems({"Keys & identities","Notepad"}); navigation->setMaximumWidth(185);
        split->addWidget(navigation);
        tabs = new QTabWidget;
        tabs->tabBar()->hide();
        buildKeys(); buildText();
        split->addWidget(tabs); split->setStretchFactor(1,1);
        connect(navigation,&QListWidget::currentRowChanged,tabs,&QTabWidget::setCurrentIndex);
        connect(tabs,&QTabWidget::currentChanged,navigation,[navigation](int row) { navigation->setCurrentRow(row); });
        connect(tabs,&QTabWidget::currentChanged,this,[this](int index) {
            if (index == 1) updateSelection();
        });
        navigation->setCurrentRow(0);
        layout->addWidget(split);
        sessionWarning = new QLabel;
        sessionWarning->setWordWrap(true); layout->addWidget(sessionWarning);
        applyPreferences({});
        root->addWidget(sessionPage);
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
                    QJsonObject result{{"ok",ok}}; if(ok) result.insert("data",data); else result.insert("error","Request denied, cancelled or failed");
                    auto bytes=QJsonDocument(result).toJson(QJsonDocument::Compact); bytes.append('\n'); socket->write(bytes); bytes.fill('\0'); socket->disconnectFromServer();
                };
                if(operation=="lock") {if(caller!="dom0" || !sessionLock) {reply(false,{}); return;} endSession(true); reply(ending,{}); socket->waitForBytesWritten(1000); return;}
                if(caller=="dom0" || (operation!="sign" && operation!="decrypt") || !object.value("text").isString() || object.value("text").toString().toUtf8().size()>1024*1024 || rpcBusy || pending) {reply(false,{}); return;}
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
                QJsonObject fields{{"text",object.value("text")}}; if(operation=="sign") fields.insert("fingerprint",fp);
                performCrypto(operation,fields,[this,guard,reply](bool ok,const QJsonObject& data) {rpcBusy=false; if(guard) reply(ok,data);},0,guard,true);
            });
        }
    }

    void applyPreferences(const QJsonObject& value) {
        preferences=value;
        autoLock=value.value("auto_lock").toBool(); focusLock=value.value("lock_on_focus_loss").toBool(); sessionLock=value.value("lock_on_session_events").toBool();
        clipboardSeconds=value.value("clipboard_clear_seconds").toInt(); qubesEnabled=value.value("qubes_rpc").toBool();
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
        else custom=false;
        if(custom) {
            palette.setColor(QPalette::Window,background); palette.setColor(QPalette::WindowText,text); palette.setColor(QPalette::Base,base); palette.setColor(QPalette::AlternateBase,background);
            palette.setColor(QPalette::Text,text); palette.setColor(QPalette::Button,background); palette.setColor(QPalette::ButtonText,text); palette.setColor(QPalette::Highlight,accent); palette.setColor(QPalette::HighlightedText,Qt::white);
            palette.setColor(QPalette::ToolTipBase,base); palette.setColor(QPalette::ToolTipText,text); palette.setColor(QPalette::PlaceholderText,muted);
            for(auto role:{QPalette::Text,QPalette::WindowText,QPalette::ButtonText}) palette.setColor(QPalette::Disabled,role,muted);
            palette.setColor(QPalette::Link,accent);
        }
        qApp->setPalette(palette);
        clipboardTimer.stop(); selectionTimer.stop();
        if(clipboardSeconds>0) { if(qApp->clipboard()->ownsClipboard()) clipboardTimer.start(clipboardSeconds*1000); if(qApp->clipboard()->ownsSelection()) selectionTimer.start(clipboardSeconds*1000); }
        if(sessionWarning) sessionWarning->setText(autoLock?"Locks after "+QString::number(idleTimeoutSeconds/60)+" minutes idle. Change in Settings.":"Auto-lock is off. Press Ctrl+L to lock. Change in Settings.");
        configureQubes();
    }

    void wireClipboard() {
        clipboardTimer.setSingleShot(true); selectionTimer.setSingleShot(true);
        connect(qApp->clipboard(),&QClipboard::dataChanged,this,[this] { clipboardTimer.stop(); if(clipboardSeconds>0 && qApp->clipboard()->ownsClipboard()) clipboardTimer.start(clipboardSeconds*1000); });
        connect(qApp->clipboard(),&QClipboard::selectionChanged,this,[this] { selectionTimer.stop(); if(clipboardSeconds>0 && qApp->clipboard()->ownsSelection()) selectionTimer.start(clipboardSeconds*1000); });
        connect(&clipboardTimer,&QTimer::timeout,this,[] { if(qApp->clipboard()->ownsClipboard()) qApp->clipboard()->clear(); });
        connect(&selectionTimer,&QTimer::timeout,this,[] { if(qApp->clipboard()->ownsSelection()) qApp->clipboard()->clear(QClipboard::Selection); });
    }

    void settingsDialog() {
        if(!unlocked || pending) return;
        QDialog dialog(this); dialog.setWindowTitle("Vault settings"); dialog.setMinimumWidth(540);
        auto* layout=new QVBoxLayout(&dialog); auto* form=new QFormLayout;
        auto* enable=new QCheckBox("Lock after inactivity"); enable->setChecked(autoLock); form->addRow(enable);
        auto* minutes=new QSlider(Qt::Horizontal); minutes->setRange(1,60); minutes->setValue(idleTimeoutSeconds/60); minutes->setEnabled(autoLock);
        auto* minuteLabel=new QLabel; auto updateMinutes=[=] {minuteLabel->setText(QString::number(minutes->value())+" minutes");}; updateMinutes();
        auto* row=new QHBoxLayout; row->addWidget(minutes); row->addWidget(minuteLabel); form->addRow("Inactivity timeout",row);
        connect(enable,&QCheckBox::toggled,minutes,&QWidget::setEnabled); connect(minutes,&QSlider::valueChanged,&dialog,updateMinutes);
        auto* focus=new QCheckBox("Lock when switching away from PGPCrypt"); focus->setChecked(focusLock); form->addRow(focus);
        auto* events=new QCheckBox("Lock on desktop lock, suspend or Qubes lock request"); events->setChecked(sessionLock); form->addRow(events);
        auto* clip=new QCheckBox("Clear text copied from PGPCrypt"); clip->setChecked(clipboardSeconds>0); form->addRow(clip);
        auto* seconds=new QSlider(Qt::Horizontal); seconds->setRange(5,1800); seconds->setValue(clipboardSeconds>0?clipboardSeconds:30); seconds->setEnabled(clipboardSeconds>0);
        auto* secondLabel=new QLabel; auto updateSeconds=[=] {secondLabel->setText(QString::number(seconds->value()/60)+"m "+QString::number(seconds->value()%60)+"s");}; updateSeconds();
        auto* clipRow=new QHBoxLayout; clipRow->addWidget(seconds); clipRow->addWidget(secondLabel); form->addRow("Clipboard delay",clipRow);
        connect(clip,&QCheckBox::toggled,seconds,&QWidget::setEnabled); connect(seconds,&QSlider::valueChanged,&dialog,updateSeconds);
        auto* theme=new QComboBox;
        theme->addItem("Light","light"); theme->addItem("Warm light","warm-light"); theme->addItem("Dark","dark"); theme->addItem("Nord","nord"); theme->addItem("Solarized light","solarized-light"); theme->addItem("Solarized dark","solarized-dark");
        auto savedTheme=preferences.value("theme").toString("light"); if(savedTheme=="solarized") savedTheme="solarized-dark";
        theme->setCurrentIndex(qMax(0,theme->findData(savedTheme))); form->addRow("Theme",theme);
        auto* qubes=new QCheckBox("Allow requests from other Qubes while unlocked"); qubes->setChecked(qubesEnabled); form->addRow(qubes);
        auto* qubesHint=new QLabel("Other Qubes can ask this vault to sign or decrypt. You approve each request here; private keys stay in this Qube. A dom0 policy must allow the client first."); qubesHint->setWordWrap(true); form->addRow(qubesHint);
        auto* qubesHelp=new QPushButton("Qubes setup details…"); form->addRow(qubesHelp);
        connect(qubesHelp,&QPushButton::clicked,&dialog,[&] {QMessageBox::information(&dialog,"Qubes requests","This enables the local PGPCrypt service only while the vault is open.\n\nInstall a named-client qrexec policy in dom0 separately. The setup guide is /usr/share/doc/pgpcrypt/design/QUBES.md; policy examples are in /usr/share/doc/pgpcrypt/source.tar.gz. Each request shows its source Qube and content for your approval.\n\nAutomatic host locking also needs the separate dom0 lock hook and the lock-events setting above. Do not enable requests from untrusted clients.");});
        layout->addLayout(form);
        auto* hint=new QLabel("Settings are encrypted in this vault. Clipboard expiry cannot erase copies kept by other apps or Qubes."); hint->setWordWrap(true); layout->addWidget(hint);
        auto* convert=new QPushButton("Save converted vault copy…"); layout->addWidget(convert); connect(convert,&QPushButton::clicked,&dialog,[&] {dialog.reject(); convertVault();});
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); layout->addWidget(buttons); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);
        if(dialog.exec()!=QDialog::Accepted) return;
        QJsonObject value{{"auto_lock",enable->isChecked()},{"lock_on_focus_loss",focus->isChecked()},{"lock_on_session_events",events->isChecked()},{"clipboard_clear_seconds",clip->isChecked()?seconds->value():0},{"theme",theme->currentData().toString()},{"qubes_rpc",qubes->isChecked()}};
        request("settings_set",{{"idle_timeout_seconds",minutes->value()*60},{"preferences",value}},[this](bool ok,const QJsonObject& data) {if(ok) {idleTimeoutSeconds=data.value("idle_timeout_seconds").toInt(300); applyPreferences(data.value("preferences").toObject());}});
    }

    void buildKeys() {
        auto* page = new QWidget; auto* layout = new QVBoxLayout(page);
        search = new QLineEdit; search->setPlaceholderText("Filter identities or fingerprints…"); layout->addWidget(search);
        keys = new QTableWidget(0,5); keys->setHorizontalHeaderLabels({"Default","Identity","Key material","Status","Fingerprint"});
        keys->setSelectionBehavior(QAbstractItemView::SelectRows); keys->setSelectionMode(QAbstractItemView::SingleSelection);
        keys->setEditTriggers(QAbstractItemView::NoEditTriggers); keys->setAlternatingRowColors(true);
        keys->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch); keys->horizontalHeader()->setSectionResizeMode(4,QHeaderView::ResizeToContents);
        keys->verticalHeader()->hide(); keys->setMinimumHeight(190); layout->addWidget(keys,2);
        connect(search,&QLineEdit::textChanged,this,[this](const QString& term) {
            for(int row=0;row<keys->rowCount();++row) keys->setRowHidden(row,!keys->item(row,1)->text().contains(term,Qt::CaseInsensitive) && !keys->item(row,4)->text().contains(term,Qt::CaseInsensitive));
        });
        details = new QLabel("Select a key to inspect its full fingerprint."); details->setTextFormat(Qt::PlainText); details->setTextInteractionFlags(Qt::TextSelectableByMouse); details->setWordWrap(true); layout->addWidget(details);
        connect(keys,&QTableWidget::itemSelectionChanged,this,[this] {
            const int row=keys->currentRow(); if(row<0) return;
            details->setText(keys->item(row,1)->text()+"\n"+keys->item(row,4)->text()+"\n"+keys->item(row,4)->data(Qt::UserRole+2).toString()+"\nCheck this fingerprint through an independent channel.");
        });
        auto* actions = new QHBoxLayout;
        auto* publicExport = new QPushButton("Show public export"); actions->addWidget(publicExport);
        connect(publicExport,&QPushButton::clicked,this,[this] {
            const int row=keys->currentRow(); if(row<0) { fail("Select a key"); return; }
            request("public_export",{{"fingerprint",keys->item(row,4)->text()}},[this](bool ok,const QJsonObject& data) { if(ok) { outputIsEncrypted=false; output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1); statusBar()->showMessage("Public export: publishing it exposes its identities"); } });
        });
        layout->addLayout(actions);
        auto* backupActions = new QHBoxLayout;
        auto* privateExport = new QPushButton("Show private key"); backupActions->addWidget(privateExport);
        connect(privateExport,&QPushButton::clicked,this,[this] {
            const int row=keys->currentRow(); if(row<0 || !keys->item(row,4)->data(Qt::UserRole+5).toBool()) { fail("Select a private key"); return; }
            const bool protectedKey=keys->item(row,4)->data(Qt::UserRole+3).toBool();
            const auto message=protectedKey?QString("Display the password-protected private key for backup? Copying it puts it outside the vault."):QString("This key contains private packets without password protection. Anyone who gets those packets can use them. Display it for backup?");
            if(QMessageBox::question(this,"Export private key",message) == QMessageBox::Yes)
                exportSelected("private_export");
        });
        auto* revocation = new QPushButton("Show revocation certificate"); backupActions->addWidget(revocation);
        connect(revocation,&QPushButton::clicked,this,[this] {
            if(QMessageBox::question(this,"Revocation certificate","Anyone with this certificate can revoke your key. Keep an offline backup. Creating or displaying it does not revoke the key.") == QMessageBox::Yes)
                exportSelected("revocation_export");
        });
        auto* protect = new QPushButton("Set / change / remove key password…"); backupActions->addWidget(protect);
        connect(protect,&QPushButton::clicked,this,[this] { protectKeyDialog(); });
        auto* subkeys=new QPushButton("Manage subkeys…"); backupActions->addWidget(subkeys);
        connect(subkeys,&QPushButton::clicked,this,[this] { subkeysDialog(); });
        layout->addLayout(backupActions);
        auto* lower = new QTabWidget;
        auto* generatePage = new QWidget; auto* generateLayout = new QVBoxLayout(generatePage);
        auto* description = new QLabel("Create a key with optional email, comment and password. A revocation certificate is saved in the vault for emergencies.");
        description->setWordWrap(true); generateLayout->addWidget(description);
        auto* generate = new QPushButton("Create key…"); generateLayout->addWidget(generate); generateLayout->addStretch();
        connect(generate,&QPushButton::clicked,this,[this] { createKeyDialog(); });
        lower->addTab(generatePage,"New identity");
        auto* importPage = new QWidget; auto* importLayout = new QVBoxLayout(importPage);
        importText=editor("Paste one armored public or private key…"); importLayout->addWidget(importText);
        auto* importButton = new QPushButton("Import into vault"); importLayout->addWidget(importButton);
        connect(importButton,&QPushButton::clicked,this,[this] { request("import",{{"text",importText->toPlainText()}},[this](bool ok,const QJsonObject&) { if(ok) { importText->clear(); refreshKeys(); } }); });
        lower->addTab(importPage,"Import key"); layout->addWidget(lower,1);
        tabs->addTab(page,"Keys");
    }

    void exportSelected(const QString& operation) {
        const int row=keys->currentRow(); if(row<0) { fail("Select a key"); return; }
        QJsonObject fields{{"fingerprint",keys->item(row,4)->text()}};
        performCrypto(operation,fields,[this,operation](bool ok,const QJsonObject& data) {
            if(ok) {
                outputIsEncrypted=false; output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1);
                statusBar()->showMessage(operation=="revocation_export"?"Revocation certificate: back up privately; do not publish until revoking.":(data.value("protected").toBool()?"Private export: protected by its separate key password.":"Private export includes unprotected secret packets; keep the text private."));
            }
        });
    }

    void subkeysDialog() {
        const int row=keys->currentRow(); if(row<0) {fail("Select a key"); return;}
        const auto fp=keys->item(row,4)->text(); const bool secret=keys->item(row,4)->data(Qt::UserRole+5).toBool();
        request("subkeys",{{"fingerprint",fp}},[this,fp,secret](bool ok,const QJsonObject& data) {
            if(!ok) return;
            QDialog dialog(this); dialog.setWindowTitle("Primary key and subkeys"); dialog.resize(950,450); auto* layout=new QVBoxLayout(&dialog);
            auto* label=new QLabel("Primary fingerprint: "+fp+"\nSubkeys keep the same OpenPGP identity. Adding one requires the primary private key to certify it."); label->setTextFormat(Qt::PlainText); label->setWordWrap(true); layout->addWidget(label);
            auto* table=new QTableWidget(0,6); table->setHorizontalHeaderLabels({"Role","Fingerprint","Algorithm","Capabilities","Expires","Status"}); table->setEditTriggers(QAbstractItemView::NoEditTriggers); layout->addWidget(table);
            for(const auto& value:data.value("keys").toArray()) {const auto key=value.toObject(); const int row=table->rowCount(); table->insertRow(row);
                QStringList fields{key.value("primary").toBool()?"Primary":"Subkey",key.value("fingerprint").toString(),key.value("algorithm").toString(),key.value("capabilities").toString(),key.value("expires_at").isNull()?"Never":QDateTime::fromSecsSinceEpoch(key.value("expires_at").toInteger(),QTimeZone::UTC).toString(Qt::ISODate),key.value("status").toString()};
                for(int column=0;column<fields.size();++column) table->setItem(row,column,new QTableWidgetItem(fields[column]));
            }
            table->resizeColumnsToContents(); auto* add=new QPushButton("Add subkey…"); add->setEnabled(secret); layout->addWidget(add);
            connect(add,&QPushButton::clicked,&dialog,[&] {dialog.accept();});
            auto* close=new QDialogButtonBox(QDialogButtonBox::Close); layout->addWidget(close); connect(close,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
            if(dialog.exec()==QDialog::Accepted && !ending) addSubkeyDialog(fp);
        });
    }

    void addSubkeyDialog(const QString& fp) {
        QDialog dialog(this); dialog.setWindowTitle("Add subkey"); auto* form=new QFormLayout(&dialog);
        auto* purpose=new QComboBox; purpose->addItem("Encryption (transport and storage)","encrypt"); purpose->addItem("Signing","sign"); purpose->addItem("Authentication","authenticate"); form->addRow("Purpose",purpose);
        auto* algorithm=new QComboBox; algorithm->addItem("Ed25519 / Cv25519","cv25519"); for(int bits:{2048,4096}) algorithm->addItem("RSA "+QString::number(bits),"rsa"+QString::number(bits));
        algorithm->addItem("NIST P-256","p256"); algorithm->addItem("NIST P-384","p384"); algorithm->addItem("NIST P-521","p521"); form->addRow("Algorithm",algorithm);
        auto* expiry=new QCheckBox("Set expiry"); expiry->setChecked(true); auto* date=new QDateTimeEdit(QDateTime::currentDateTimeUtc().addYears(1)); date->setCalendarPopup(true); date->setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'");
        form->addRow(expiry); form->addRow("Expires",date); connect(expiry,&QCheckBox::toggled,date,&QWidget::setEnabled);
        auto* pass=new QLineEdit; auto* confirm=new QLineEdit; for(auto* field:{pass,confirm}) {field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText);}
        form->addRow("New subkey password (optional)",pass); form->addRow("Confirm subkey password",confirm);
        auto* note=new QLabel("Expiry must be within the primary key’s lifetime. Export the updated public key after adding a subkey."); note->setWordWrap(true); form->addRow(note);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); form->addRow(error); auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel); form->addRow(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); connect(buttons,&QDialogButtonBox::accepted,&dialog,[&] {if(pass->text()!=confirm->text()) {error->setText("Passwords do not match"); return;} if(expiry->isChecked() && date->dateTime()<=QDateTime::currentDateTimeUtc().addSecs(60)) {error->setText("Choose a future expiry"); return;} dialog.accept();});
        if(dialog.exec()!=QDialog::Accepted) {pass->clear(); confirm->clear(); return;}
        QJsonObject options{{"algorithm",algorithm->currentData().toString()},{"purpose",purpose->currentData().toString()},{"expires_at",expiry->isChecked()?QJsonValue(date->dateTime().toSecsSinceEpoch()):QJsonValue(QJsonValue::Null)}};
        QJsonObject fields{{"fingerprint",fp},{"subkey_options",options},{"new_password",pass->text()}}; pass->clear(); confirm->clear();
        performCrypto("add_subkey",fields,[this](bool ok,const QJsonObject&) {if(ok) {refreshKeys(); statusBar()->showMessage("Subkey added. Export and distribute the updated public certificate.");}});
    }

    void createKeyDialog() {
        QDialog dialog(this); dialog.setWindowTitle("Create OpenPGP key"); dialog.setMinimumWidth(560);
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
        auto* transport=new QCheckBox("Encrypt communications"); transport->setChecked(true);
        auto* storage=new QCheckBox("Encrypt storage"); storage->setChecked(true);
        auto* authentication=new QCheckBox("Authentication");
        form->addRow("Capabilities",certify); form->addRow(signing); form->addRow(transport); form->addRow(storage); form->addRow(authentication);
        auto updateLayout=[=] {
            const bool rsa=algorithm->currentData().toString().startsWith("rsa");
            keyLayout->setEnabled(rsa); if(!rsa) keyLayout->setCurrentIndex(0);
            const bool subkeys=keyLayout->currentData().toString()=="subkeys";
            certify->setEnabled(!subkeys); if(subkeys) certify->setChecked(true);
        };
        connect(algorithm,&QComboBox::currentIndexChanged,&dialog,updateLayout); connect(keyLayout,&QComboBox::currentIndexChanged,&dialog,updateLayout);
        auto* expire=new QCheckBox("Expire on"); expire->setChecked(true);
        auto* date=new QDateTimeEdit(QDateTime::currentDateTimeUtc().addYears(2)); date->setCalendarPopup(true); date->setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'");
        connect(expire,&QCheckBox::toggled,date,&QWidget::setEnabled); form->addRow(expire,date);
        auto* pass=new QLineEdit; auto* confirm=new QLineEdit;
        for(auto* field : {pass,confirm}) { field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase); }
        form->addRow("Private-key password/passphrase (optional)",pass); form->addRow("Confirm password/passphrase",confirm);
        layout->addLayout(form);
        auto* hint=new QLabel("Leave both passwords blank for no separate key password. A key password also protects private-key exports. Legacy keys can be imported."); hint->setWordWrap(true); layout->addWidget(hint);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); error->setWordWrap(true); layout->addWidget(error);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel); layout->addWidget(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        connect(buttons,&QDialogButtonBox::accepted,&dialog,[=,&dialog] {
            if(name->text().trimmed().isEmpty()) { error->setText("Enter a name or pseudonym."); return; }
            if(pass->text()!=confirm->text()) { error->setText("Passwords/passphrases do not match."); return; }
            if(!certify->isChecked() && !signing->isChecked() && !transport->isChecked() && !storage->isChecked() && !authentication->isChecked()) { error->setText("Select at least one capability."); return; }
            if(expire->isChecked() && date->dateTime() <= QDateTime::currentDateTimeUtc().addSecs(60)) { error->setText("Choose an expiry at least one minute in the future."); return; }
            dialog.accept();
        });
        if(dialog.exec()!=QDialog::Accepted) { pass->clear(); confirm->clear(); return; }
        QJsonObject options{{"name",name->text()},{"email",email->text()},{"comment",comment->text()},{"algorithm",algorithm->currentData().toString()},{"layout",keyLayout->currentData().toString()},
            {"certification",certify->isChecked()},{"signing",signing->isChecked()},{"transport_encryption",transport->isChecked()},{"storage_encryption",storage->isChecked()},{"authentication",authentication->isChecked()},
            {"expires_at",expire->isChecked()?QJsonValue(date->dateTime().toSecsSinceEpoch()):QJsonValue(QJsonValue::Null)}};
        QJsonObject fields{{"key_options",options},{"password",pass->text()}}; pass->clear(); confirm->clear();
        request("generate",fields,[this](bool ok,const QJsonObject&) { if(ok) { refreshKeys(); statusBar()->showMessage("Key and emergency revocation certificate saved inside encrypted vault"); } });
    }

    void protectKeyDialog() {
        const int row=keys->currentRow(); if(row<0) { fail("Select a private key"); return; }
        const QString fingerprint=keys->item(row,4)->text();
        QDialog dialog(this); dialog.setWindowTitle("Private-key password"); auto* form=new QFormLayout(&dialog);
        auto* current=new QLineEdit; auto* pass=new QLineEdit; auto* confirm=new QLineEdit;
        for(auto* field : {current,pass,confirm}) { field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase); }
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

    void refreshKeys(std::function<void()> after = {}) {
        request("list",{},[this,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            QStringList chosenRecipients;
            for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) chosenRecipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
            const auto previousSigner=signingChoice->currentData().toString();
            defaultSigner=data.value("default_signing_key").toString();
            QSignalBlocker signingBlock(signingChoice), recipientsBlock(recipientChoices);
            keys->setRowCount(0); recipientChoices->clear(); signingChoice->clear(); signingChoice->addItem("Select a signing key",QString());
            for(const auto& entry:data.value("keys").toArray()) {
                const auto key=entry.toObject(); const int row=keys->rowCount(); keys->insertRow(row);
                const auto fp=key.value("fingerprint").toString();
                keys->setItem(row,0,new QTableWidgetItem(fp==defaultSigner?"Default":""));
                QStringList identities; for(const auto& value:key.value("identities").toArray()) identities.append(value.toString());
                const auto identity=identities.isEmpty()?fp:identities.join("; ");
                keys->setItem(row,1,new QTableWidgetItem(identity));
                keys->setItem(row,2,new QTableWidgetItem(key.value("has_secret").toBool()?(key.value("secret_protected").toBool()?"Private (password)":(key.value("secret_any_protected").toBool()?"Private (mixed protection)":"Private (no password)")):"Public only"));
                keys->setItem(row,3,new QTableWidgetItem(key.value("status").toString()));
                auto* fingerprint=new QTableWidgetItem(fp); fingerprint->setData(Qt::UserRole+1,key.value("can_sign").toBool());
                fingerprint->setData(Qt::UserRole+3,key.value("secret_protected").toBool());
                fingerprint->setData(Qt::UserRole+4,key.value("has_revocation").toBool());
                fingerprint->setData(Qt::UserRole+5,key.value("has_secret").toBool());
                QStringList capabilities; for(const auto& value:key.value("capabilities").toArray()) capabilities.append(value.toString());
                const auto expires=key.value("expires_at");
                fingerprint->setData(Qt::UserRole+2,key.value("algorithm").toString()+" • Expires: "+(expires.isNull()?QString("never"):QDateTime::fromSecsSinceEpoch(expires.toInteger(),QTimeZone::UTC).toString(Qt::ISODate))+"\nCapabilities: "+capabilities.join("; "));
                keys->setItem(row,4,fingerprint);
                if(key.value("can_encrypt").toBool()) {
                    auto* recipient=new QListWidgetItem(identity+" — "+fp,recipientChoices); recipient->setData(Qt::UserRole,fp); recipient->setToolTip(fp);
                    recipient->setFlags(Qt::ItemIsEnabled|Qt::ItemIsUserCheckable|Qt::ItemIsSelectable);
                    recipient->setCheckState(chosenRecipients.contains(fp)?Qt::Checked:Qt::Unchecked);
                }
                if(key.value("can_sign").toBool()) { signingChoice->addItem(identity+" — "+fp,fp); signingChoice->setItemData(signingChoice->count()-1,fp+(key.value("signing_password_required").toBool()?"\nPassword required to sign":"\nSigning key available without a password"),Qt::ToolTipRole); }
            }
            const auto wanted=previousSigner.isEmpty()?defaultSigner:previousSigner;
            signingChoice->setCurrentIndex(qMax(0,signingChoice->findData(wanted)));
            updateSelection();
            signingBlock.unblock(); recipientsBlock.unblock();
            if(after) after();
        });
    }

    void buildText() {
        auto* page=new QWidget; auto* layout=new QVBoxLayout(page);
        auto* label=new QLabel("Encrypt for selected recipients, or sign readable text with your key. Use Open message and Save output for files."); label->setWordWrap(true); layout->addWidget(label);
        auto* form=new QFormLayout;
        recipientChoices=new QListWidget; recipientChoices->setMaximumHeight(125); form->addRow("Encrypt to",recipientChoices);
        signingChoice=new QComboBox; signingChoice->setMinimumContentsLength(24); signingChoice->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        signingChoice->addItem("Select a signing key",QString()); form->addRow("Signing key",signingChoice); layout->addLayout(form);
        auto* defaults=new QHBoxLayout;
        auto* setDefault=new QPushButton("Use signing key as default"); defaults->addWidget(setDefault);
        auto* clearDefault=new QPushButton("Clear default"); defaults->addWidget(clearDefault); defaults->addStretch(); layout->addLayout(defaults);
        defaultKeyLabel=new QLabel; defaultKeyLabel->setTextFormat(Qt::PlainText); defaultKeyLabel->setWordWrap(true); layout->addWidget(defaultKeyLabel);
        connect(setDefault,&QPushButton::clicked,this,[this] {
            const auto fp=signingChoice->currentData().toString(); if(fp.isEmpty()) { fail("Choose a signing key on the notepad"); return; }
            saveDefaultKey(fp);
        });
        connect(clearDefault,&QPushButton::clicked,this,[this] { saveDefaultKey({}); });
        connect(signingChoice,&QComboBox::currentIndexChanged,this,[this] { updateSelection(); });
        connect(recipientChoices,&QListWidget::itemChanged,this,[this] { updateSelection(); });
        selectionSummary=new QLabel; selectionSummary->setTextFormat(Qt::PlainText); selectionSummary->setWordWrap(true); layout->addWidget(selectionSummary);
        input=editor("Paste plaintext or an armored OpenPGP message…"); output=editor("Result appears here after the operation succeeds…",true);
        auto* panes=new QSplitter(Qt::Vertical); panes->addWidget(input); panes->addWidget(output); layout->addWidget(panes,1);
        auto* actions=new QHBoxLayout;
        for(const auto& name:QStringList{"Encrypt","Decrypt","Sign","Verify"}) {
            auto* button=new QPushButton(name); actions->addWidget(button);
            connect(button,&QPushButton::clicked,this,[this,name] { textAction(name.toLower()); });
        }
        auto* clear=new QPushButton("Clear"); actions->addWidget(clear);
        connect(clear,&QPushButton::clicked,this,[this]{ input->clear(); output->clear(); outputIsEncrypted=false; });
        layout->addLayout(actions);
        auto* files=new QHBoxLayout;
        auto* openMessage=new QPushButton("Open message…"); files->addWidget(openMessage);
        auto* saveOutput=new QPushButton("Save output…"); files->addWidget(saveOutput); files->addStretch(); layout->addLayout(files);
        saveOutput->setEnabled(false); connect(output,&QPlainTextEdit::textChanged,saveOutput,[this,saveOutput] {saveOutput->setEnabled(!output->toPlainText().isEmpty());});
        connect(openMessage,&QPushButton::clicked,this,[this] {const auto filename=chooseMessagePath(false); if(!filename.isEmpty()) loadMessageFile(filename);});
        connect(saveOutput,&QPushButton::clicked,this,[this] {
            if(!outputIsEncrypted && QMessageBox::question(this,"Save readable output","This saves readable text or key material outside the vault. Keep private messages, private keys and revocation certificates private. Continue?",QMessageBox::Save|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Save) return;
            const auto filename=chooseMessagePath(true); if(!filename.isEmpty()) saveOutputFile(filename);
        });
        layout->addWidget(new QLabel("Undo history is disabled. Clipboard managers may retain copied text after locking."));
        tabs->addTab(page,"Notepad");
    }

    QString chooseMessagePath(bool save) {
        const bool armored=output->toPlainText().startsWith("-----BEGIN PGP ");
        const auto initial=save?QDir::home().filePath(armored?"message.asc":"message.txt"):QDir::homePath();
        QFileDialog dialog(this,save?"Save output":"Open message",initial);
        dialog.setOption(QFileDialog::DontUseNativeDialog); dialog.setOption(QFileDialog::DontResolveSymlinks);
        dialog.setAcceptMode(save?QFileDialog::AcceptSave:QFileDialog::AcceptOpen);
        dialog.setFileMode(save?QFileDialog::AnyFile:QFileDialog::ExistingFile);
        dialog.setNameFilters({"Messages (*.asc *.pgp *.txt)","All files (*)"});
        if(save) dialog.setDefaultSuffix(armored?"asc":"txt");
        if(dialog.exec()!=QDialog::Accepted || dialog.selectedFiles().isEmpty()) return {};
        return QFileInfo(dialog.selectedFiles().first()).absoluteFilePath();
    }

    bool loadMessageFile(const QString& filename) {
        const auto encoded=QFile::encodeName(filename);
        const int descriptor=::open(encoded.constData(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if(descriptor<0) {fail("Cannot open message. Choose a readable file, not a symbolic link."); return false;}
        struct stat metadata{};
        if(::fstat(descriptor,&metadata)!=0 || !S_ISREG(metadata.st_mode) || metadata.st_size<0 || metadata.st_size>MaxMessageInput) {::close(descriptor); fail("Choose a regular text message no larger than 4 MiB."); return false;}
        QFile file;
        if(!file.open(descriptor,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)) {::close(descriptor); fail("Cannot read message."); return false;}
        auto bytes=file.read(MaxMessageInput+1);
        if(file.error()!=QFileDevice::NoError || bytes.size()>MaxMessageInput || bytes.contains('\0')) {bytes.fill('\0'); fail("Choose a UTF-8 text message no larger than 4 MiB."); return false;}
        QStringDecoder decoder(QStringDecoder::Utf8); QString text=decoder(bytes); bytes.fill('\0');
        if(decoder.hasError()) {fail("This file is not UTF-8 text. Open an armored (.asc) message instead."); return false;}
        input->setPlainText(text); outputIsEncrypted=false; output->clear(); tabs->setCurrentIndex(1);
        statusBar()->showMessage("Message loaded into Input. Choose Decrypt, Verify, Encrypt or Sign."); return true;
    }

    bool saveOutputFile(const QString& filename) {
        const auto target=QFileInfo(filename).absoluteFilePath();
        const auto vaultPath=absoluteVaultPath(path->text());
        for(const auto& reserved:QStringList{vaultPath,vaultPath+".lock"}) {
            if(target==reserved || (QFileInfo::exists(target) && QFileInfo(target).canonicalFilePath()==QFileInfo(reserved).canonicalFilePath())) {fail("Choose a message filename. The open vault and its lock file cannot be overwritten."); return false;}
        }
        const auto encoded=QFile::encodeName(target); struct stat metadata{};
        if(::lstat(encoded.constData(),&metadata)==0) {
            if(!S_ISREG(metadata.st_mode)) {fail("Choose a regular file, not a symbolic link."); return false;}
        } else if(errno!=ENOENT) {fail("Cannot access the output location."); return false;}
        auto bytes=output->toPlainText().toUtf8();
        if(bytes.isEmpty() || bytes.size()>MaxMessageOutput) {bytes.fill('\0'); fail("Output must contain text no larger than 4 MiB."); return false;}
        // A same-folder private temporary file plus rename keeps partial output
        // out of the final file. rename never follows a destination symlink.
        QTemporaryFile file(QFileInfo(target).absolutePath()+"/.pgpcrypt-message-XXXXXX");
        if(!file.open() || !file.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)) {bytes.fill('\0'); fail("Cannot create a private output file. Choose a writable folder."); return false;}
        const bool written=file.write(bytes)==bytes.size(); bytes.fill('\0');
        if(!written || !file.flush() || ::fsync(file.handle())!=0) {fail("Output could not be saved completely. Try another folder."); return false;}
        if(::rename(QFile::encodeName(file.fileName()).constData(),encoded.constData())!=0) {fail("Cannot save output. Check folder permissions."); return false;}
        file.setAutoRemove(false);
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
        signer=signingChoice->currentData().toString();
        QStringList recipients;
        for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) recipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
        selectionSummary->setText("Recipients: "+(recipients.isEmpty()?QString("none"):recipients.join(", "))+"\nSigner: "+(signer.isEmpty()?QString("none"):signer));
        defaultKeyLabel->setText(defaultSigner.isEmpty()?"Default signing key: none":"Default signing key: "+defaultSigner+(signingChoice->findData(defaultSigner)<0?" (unavailable for signing)":""));
    }

    void textAction(const QString& operation, std::function<void()> after = {}) {
        if(operation=="sign" && signer.isEmpty()) { fail("Select a signing key on the notepad"); return; }
        QJsonArray recipients;
        for(int i=0;i<recipientChoices->count();++i) if(recipientChoices->item(i)->checkState()==Qt::Checked) recipients.append(recipientChoices->item(i)->data(Qt::UserRole).toString());
        QJsonObject fields{{"text",input->toPlainText()},{"fingerprint",signer},{"recipients",recipients}};
        outputIsEncrypted=false; output->clear();
        performCrypto(operation,fields,[this,operation,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            outputIsEncrypted=operation=="encrypt"; output->setPlainText(data.value("text").toString());
            if(operation=="verify" || operation=="decrypt") {
                QStringList signers; for(const auto& fp:data.value("signers").toArray()) signers.append(fp.toString());
                statusBar()->showMessage(signers.isEmpty()?"Decrypted. No signature verified.":"Valid signature: "+signers.join(", ")+" — identity must be checked independently.");
            } else statusBar()->showMessage(operation=="encrypt"?"Encrypted. Recipient identifiers may be visible in the exported message.":"Signed text is readable. The signature identifies the signing key.");
            if(after) after();
        });
    }

    void performCrypto(const QString& operation,QJsonObject fields,Reply done,int attempt=0,QPointer<QLocalSocket> peer={},bool remoteCall=false) {
        if(remoteCall && (!peer || peer->state()!=QLocalSocket::ConnectedState)) {done(false,{}); return;}
        request(operation,fields,[this,operation,fields,done,attempt,peer,remoteCall](bool ok,const QJsonObject& data) mutable {
            if(!ok && data.value("_error_code").toString()=="password_required" && attempt<3) {
                bool accepted=true; QString pass;
                if(testing) pass=testKdbx?"":"x";
                else {
                    QDialog dialog(this); dialog.setWindowTitle("Unlock private key");
                    auto* form=new QFormLayout(&dialog); auto* prompt=new QLabel(attempt?"Password/passphrase was not accepted. Try again:":"This private key is password protected."); prompt->setWordWrap(true); form->addRow(prompt);
                    auto* entry=new QLineEdit; entry->setEchoMode(QLineEdit::Password); entry->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText|Qt::ImhNoAutoUppercase); form->addRow("Password/passphrase",entry);
                    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel); form->addRow(buttons);
                    connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept); connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); connect(entry,&QLineEdit::returnPressed,&dialog,&QDialog::accept);
                    QTimer timeout; timeout.setSingleShot(true);
                    if(remoteCall) {if(!peer || peer->state()!=QLocalSocket::ConnectedState) {done(false,{}); return;} connect(peer,&QLocalSocket::disconnected,&dialog,&QDialog::reject); connect(&timeout,&QTimer::timeout,&dialog,&QDialog::reject); timeout.start(60000);}
                    entry->setFocus(); accepted=dialog.exec()==QDialog::Accepted; pass=entry->text(); entry->clear();
                }
                if(!accepted || ending || (remoteCall && (!peer || peer->state()!=QLocalSocket::ConnectedState))) {statusBar()->showMessage("Operation cancelled"); done(false,{}); return;}
                fields.insert("password",pass); pass.fill(QChar('\0')); performCrypto(operation,fields,done,attempt+1,peer,remoteCall); return;
            }
            if(!ok && data.value("_error_code").toString()=="password_required") fail("Could not unlock private key");
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

    void testSettingsAndQubes(std::function<void()> after) {
        if(autoLock || focusLock || sessionLock || clipboardSeconds!=0 || tabs->count()!=2) {fail("New-vault default settings or notes removal failed"); return;}
        QEvent deactivate(QEvent::ApplicationDeactivate); QCoreApplication::sendEvent(qApp,&deactivate);
        if(ending) {fail("Focus loss locked with opt-in disabled"); return;}
        QJsonObject value{{"auto_lock",false},{"lock_on_focus_loss",false},{"lock_on_session_events",false},{"clipboard_clear_seconds",0},{"theme","dark"},{"qubes_rpc",true}};
        request("settings_set",{{"preferences",value}},[this,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            applyPreferences(data.value("preferences").toObject());
            if(!rpcServer.isListening() || qApp->palette().color(QPalette::Window).lightness()>100) {fail("Theme or Qubes broker setting failed"); return;}
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
    }

    void testCreate() {
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
                testFingerprint=keys->item(0,4)->text();
                if(recipientChoices->count()!=1 || signingChoice->findData(testFingerprint)<1) { fail("Notepad key choices did not populate"); return; }
                recipientChoices->item(0)->setCheckState(Qt::Checked); signingChoice->setCurrentIndex(signingChoice->findData(testFingerprint));
                request("settings_set",{{"default_signing_key",testFingerprint}},[this](bool ok,const QJsonObject&) {
                    if(!ok) return;
                    signingChoice->setCurrentIndex(0);
                    refreshKeys([this] {
                        if(defaultSigner!=testFingerprint || signer!=testFingerprint || recipientChoices->item(0)->checkState()!=Qt::Checked) { fail("Notepad default or recipients were not restored"); return; }
                        if(!tabs->widget(1)->isAncestorOf(signingChoice) || !tabs->widget(1)->isAncestorOf(recipientChoices)) { fail("Key controls are outside the notepad"); return; }
                        testSettingsAndQubes([this] {testNotepadWorkflow();});
                    });
                });
            });
        });
    }
    void testNotepadWorkflow() {
        tabs->setCurrentIndex(1); input->setPlainText("Qt desktop private fixture");
        textAction("encrypt",[this] {
            input->setPlainText(output->toPlainText());
            textAction("decrypt",[this] {
                if(output->toPlainText()!="Qt desktop private fixture") { fail("Decryption mismatch"); return; }
                input->setPlainText("Qt signature fixture");
                textAction("sign",[this] {
                    if(!output->toPlainText().startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) {fail("Sign did not produce readable signed text"); return;}
                    input->setPlainText(output->toPlainText());
                    textAction("verify",[this] {
                        if(output->toPlainText()!="Qt signature fixture") { fail("Verification mismatch"); return; }
                        const auto fixture=QDir::home().filePath("saved-message.txt");
                        if(!saveOutputFile(fixture) || !loadMessageFile(fixture) || input->toPlainText()!="Qt signature fixture") {fail("Message save/load did not preserve text"); return;}
                        const QFileInfo saved(fixture);
                        if(saved.permissions() & (QFileDevice::ReadGroup|QFileDevice::WriteGroup|QFileDevice::ReadOther|QFileDevice::WriteOther)) {fail("Saved message is not private"); return;}
                        request("notes_set",{{"text","encrypted Qt note"}},[this](bool ok,const QJsonObject&) {
                            if(!ok) return;
                            request("notes_get",{},[this](bool ok,const QJsonObject& data) {
                                if(!ok || data.value("text").toString()!="encrypted Qt note") { fail("Notes mismatch"); return; }
                                tabs->setCurrentIndex(screenshotPath.isEmpty()?0:1);
                                QTimer::singleShot(100,this,[this] {
                                    if(!screenshotPath.isEmpty() && !grab().save(screenshotPath)) { fail("Screenshot failed"); return; }
                                    endSession(true);
                                });
                            });
                        });
                    });
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
    std::unique_ptr<QTemporaryDir> fixtureHome;
    if(selfTest) {
        fixtureHome=std::make_unique<QTemporaryDir>(QDir::tempPath()+"/pgpcrypt-ui-home-XXXXXX");
        if(!fixtureHome->isValid()) { std::fputs("Cannot create isolated test home\n",stderr); return 1; }
        qputenv("HOME",QFile::encodeName(fixtureHome->path()));
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
