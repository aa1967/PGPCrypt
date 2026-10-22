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
#include <QFormLayout>
#include <QHeaderView>
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
#include <QPushButton>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTabBar>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTimer>
#include <QTimeZone>
#include <QToolBar>
#include <QVBoxLayout>
#include <functional>
#include <cstdio>
#include <csignal>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

namespace {
constexpr int RestartLocked = 75;
constexpr qsizetype MaxFrame = 8 * 1024 * 1024;
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
    explicit Window(bool selfTest, const QString& screenshot, bool restartProbe = false)
        : testing(selfTest), restartTest(restartProbe), screenshotPath(screenshot) {
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
            if (unlocked && (activityClock.elapsed() >= idleTimeoutSeconds * 1000LL || now - lastTick > 15000 || now < lastTick)) endSession(true);
            lastTick = now;
        });
        idle.setInterval(1000);
        lastTick = QDateTime::currentMSecsSinceEpoch();
        qApp->installEventFilter(this);
        wireSessionSignals();
        if (testing) QTimer::singleShot(100, this, [this] { testCreate(); });
    }

    ~Window() override {
        ending = true;
        if (process.state() != QProcess::NotRunning) { process.kill(); process.waitForFinished(5000); }
        incoming.fill('\0');
    }

    void smoke() { QTimer::singleShot(150, qApp, &QCoreApplication::quit); }

public slots:
    void preparingForSleep(bool sleeping) { if (sleeping && unlocked) endSession(true); }
    void sessionLocked() { if (unlocked) endSession(true); }
    void screensaverChanged(bool active) { if (active && unlocked) endSession(true); }

protected:
    bool eventFilter(QObject* object, QEvent* event) override {
        if (event->type() == QEvent::KeyPress || event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseMove)
            activityClock.restart();
        if (!testing && unlocked && event->type() == QEvent::ApplicationDeactivate) endSession(true);
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
    bool unlocked = false, ending = false, testing = false, restartTest = false, notesLoaded = false;
    QString screenshotPath;
    QTemporaryDir testDirectory;
    QTimer idle;
    QElapsedTimer activityClock;
    int idleTimeoutSeconds = 300;
    qint64 lastTick = 0;
    QStackedWidget *root = nullptr;
    QWidget *sessionPage = nullptr, *lockedPage = nullptr;
    QLineEdit *path = nullptr, *password = nullptr, *confirmation = nullptr, *search = nullptr, *keyPassword = nullptr;
    QCheckBox* create = nullptr;
    QComboBox* timeoutChoice = nullptr;
    QLabel* sessionWarning = nullptr;
    QPushButton* unlockButton = nullptr;
    QLabel *lockedStatus = nullptr, *details = nullptr, *selectionSummary = nullptr;
    QTableWidget* keys = nullptr;
    QTabWidget* tabs = nullptr;
    QPlainTextEdit *importText = nullptr, *input = nullptr, *output = nullptr, *notes = nullptr;
    QAction* lockAction = nullptr;
    QString signer;
    QString testFingerprint;

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
        tabs->setEnabled(true); unlockButton->setEnabled(true);
        const bool ok = response.value("ok").toBool();
        if (!ok) fail(response.value("error").toString("Operation failed"));
        else statusBar()->showMessage("Ready • Offline");
        if (callback) callback(ok, response.value("data").toObject());
    }

    void endSession(bool restart) {
        if (ending) return;
        ending = true;
        idle.stop();
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            if (!process.waitForFinished(5000)) { ending = false; idle.start(); fail("Worker could not be stopped; vault lock is not confirmed"); return; }
        }
        unlocked = false;
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
        lockedPage = new QWidget;
        auto* outer = new QVBoxLayout(lockedPage);
        outer->setContentsMargins(100, 60, 100, 60);
        auto* title = new QLabel("PGPCrypt");
        title->setStyleSheet("font-size: 32px; font-weight: 600;");
        outer->addWidget(title);
        outer->addWidget(new QLabel("One encrypted vault for your OpenPGP identities."));
        outer->addSpacing(28);
        auto* form = new QFormLayout;
        path = new QLineEdit; path->setPlaceholderText("/home/you/Documents/private.pgpcrypt.age");
        // Avoid native file-dialog recent-file/history persistence of vault paths.
        form->addRow("Vault file",path);
        password = new QLineEdit; password->setEchoMode(QLineEdit::Password);
        password->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
        form->addRow("Passphrase",password);
        confirmation = new QLineEdit; confirmation->setEchoMode(QLineEdit::Password);
        confirmation->setInputMethodHints(password->inputMethodHints()); confirmation->setEnabled(false);
        form->addRow("Confirm",confirmation);
        create = new QCheckBox("Create a new vault (minimum 16 characters; no password reset)");
        connect(create,&QCheckBox::toggled,confirmation,&QWidget::setEnabled);
        form->addRow(create);
        outer->addLayout(form);
        unlockButton = new QPushButton("Unlock / create vault");
        outer->addWidget(unlockButton);
        connect(password,&QLineEdit::returnPressed,unlockButton,&QPushButton::click);
        connect(unlockButton,&QPushButton::clicked,this,[this] {
            if (create->isChecked() && password->text() != confirmation->text()) { fail("Passphrases do not match"); return; }
            QJsonObject fields{{"path",path->text()},{"password",password->text()}};
            const auto op = create->isChecked() ? "create" : "open";
            password->clear(); confirmation->clear();
            request(op,fields,[this](bool ok,const QJsonObject& data) {
                if (!ok) return;
                unlocked = true; lockAction->setEnabled(true); root->setCurrentWidget(sessionPage);
                applyTimeout(data.value("idle_timeout_seconds").toInt(300));
                path->clear(); lockedStatus->clear();
                activityClock.restart();
                refreshKeys([this] { if (testing) testGenerate(); });
            });
        });
        lockedStatus = new QLabel; lockedStatus->setTextFormat(Qt::PlainText); lockedStatus->setWordWrap(true); outer->addWidget(lockedStatus);
        outer->addStretch();
        auto* warning = new QLabel("Experimental • No network access or system keyring\nVault size and filename remain visible. Use disposable keys until independently reviewed.");
        warning->setWordWrap(true); outer->addWidget(warning);
        root->addWidget(lockedPage);
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
        auto* timeoutRow = new QHBoxLayout;
        timeoutRow->addWidget(new QLabel("Lock after inactivity:"));
        timeoutChoice = new QComboBox;
        for (int minutes : {1,2,5,10,15,30,60}) timeoutChoice->addItem(QString::number(minutes)+" minutes",minutes*60);
        timeoutChoice->setCurrentIndex(2);
        timeoutRow->addWidget(timeoutChoice); timeoutRow->addStretch();
        auto* saveTimeout = new QPushButton("Save timeout"); timeoutRow->addWidget(saveTimeout);
        connect(saveTimeout,&QPushButton::clicked,this,[this] {
            request("settings_set",{{"idle_timeout_seconds",timeoutChoice->currentData().toInt()}},[this](bool ok,const QJsonObject& data) {
                if(ok) { applyTimeout(data.value("idle_timeout_seconds").toInt()); statusBar()->showMessage("Vault timeout saved"); }
                else timeoutChoice->setCurrentIndex(timeoutChoice->findData(idleTimeoutSeconds));
            });
        });
        layout->addLayout(timeoutRow);
        auto* split = new QSplitter;
        auto* navigation = new QListWidget; navigation->addItems({"Keys & identities","Text workspace","Encrypted notes"}); navigation->setMaximumWidth(185);
        split->addWidget(navigation);
        tabs = new QTabWidget;
        tabs->tabBar()->hide();
        buildKeys(); buildText(); buildNotes();
        split->addWidget(tabs); split->setStretchFactor(1,1);
        connect(navigation,&QListWidget::currentRowChanged,tabs,&QTabWidget::setCurrentIndex);
        connect(tabs,&QTabWidget::currentChanged,navigation,[navigation](int row) { navigation->setCurrentRow(row); });
        connect(tabs,&QTabWidget::currentChanged,this,[this](int index) {
            if (index == 1) updateSelection();
            if (index == 2 && unlocked && !pending && !notesLoaded) request("notes_get",{},[this](bool ok,const QJsonObject& data) { if(ok) { notes->setPlainText(data.value("text").toString()); notesLoaded=true; } });
        });
        navigation->setCurrentRow(0);
        layout->addWidget(split);
        sessionWarning = new QLabel;
        sessionWarning->setWordWrap(true); layout->addWidget(sessionWarning);
        applyTimeout(300);
        root->addWidget(sessionPage);
    }

    void applyTimeout(int seconds) {
        idleTimeoutSeconds = qBound(60,seconds,3600);
        if(timeoutChoice) {
            int index=timeoutChoice->findData(idleTimeoutSeconds);
            if(index<0) { timeoutChoice->addItem(QString::number(idleTimeoutSeconds)+" seconds",idleTimeoutSeconds); index=timeoutChoice->count()-1; }
            timeoutChoice->setCurrentIndex(index);
        }
        if(sessionWarning) sessionWarning->setText("Locks on focus loss, desktop lock, suspend or "+QString::number(idleTimeoutSeconds/60)+" minutes idle. Lock discards unsaved text and restarts this session.");
    }

    void buildKeys() {
        auto* page = new QWidget; auto* layout = new QVBoxLayout(page);
        search = new QLineEdit; search->setPlaceholderText("Filter identities or fingerprints…"); layout->addWidget(search);
        keys = new QTableWidget(0,5); keys->setHorizontalHeaderLabels({"Encrypt to","Identity","Key material","Status","Fingerprint"});
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
        connect(keys,&QTableWidget::itemChanged,this,[this](QTableWidgetItem* item) {
            if(item->column()==0 && selectionSummary) updateSelection();
        });
        auto* actions = new QHBoxLayout;
        auto* chooseSigner = new QPushButton("Use selected key for signing"); actions->addWidget(chooseSigner);
        connect(chooseSigner,&QPushButton::clicked,this,[this] { const int row=keys->currentRow(); if(row<0 || !keys->item(row,4)->data(Qt::UserRole+1).toBool()) { fail("Select a valid private signing key"); return; } signer=keys->item(row,4)->text(); updateSelection(); statusBar()->showMessage("Signing key selected: "+signer); });
        auto* publicExport = new QPushButton("Show public export"); actions->addWidget(publicExport);
        connect(publicExport,&QPushButton::clicked,this,[this] {
            const int row=keys->currentRow(); if(row<0) { fail("Select a key"); return; }
            request("public_export",{{"fingerprint",keys->item(row,4)->text()}},[this](bool ok,const QJsonObject& data) { if(ok) { output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1); statusBar()->showMessage("Public export: publishing it exposes its identities"); } });
        });
        layout->addLayout(actions);
        auto* backupActions = new QHBoxLayout;
        auto* privateExport = new QPushButton("Show protected private key"); backupActions->addWidget(privateExport);
        connect(privateExport,&QPushButton::clicked,this,[this] {
            if(QMessageBox::question(this,"Export private key","Display the passphrase-protected private key for backup? Copying it puts it outside this vault's protection.") == QMessageBox::Yes)
                exportSelected("protected_private_export");
        });
        auto* revocation = new QPushButton("Show revocation certificate"); backupActions->addWidget(revocation);
        connect(revocation,&QPushButton::clicked,this,[this] {
            if(QMessageBox::question(this,"Revocation certificate","Anyone with this certificate can revoke your key. Keep an offline backup. Creating or displaying it does not revoke the key.") == QMessageBox::Yes)
                exportSelected("revocation_export");
        });
        auto* protect = new QPushButton("Protect / change key passphrase…"); backupActions->addWidget(protect);
        connect(protect,&QPushButton::clicked,this,[this] { protectKeyDialog(); });
        layout->addLayout(backupActions);
        auto* lower = new QTabWidget;
        auto* generatePage = new QWidget; auto* generateLayout = new QVBoxLayout(generatePage);
        auto* description = new QLabel("Create an OpenPGP identity with an optional email/comment, expiry, capabilities and a separate private-key passphrase. An emergency revocation certificate is saved inside the vault.");
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
        // Imported keys need their primary-key password only if no saved ticket
        // exists. Keep password entry on the normal text workspace.
        fields.insert("password",keyPassword->text()); keyPassword->clear();
        request(operation,fields,[this,operation](bool ok,const QJsonObject& data) {
            if(ok) {
                output->setPlainText(data.value("text").toString()); tabs->setCurrentIndex(1);
                statusBar()->showMessage(operation=="revocation_export"?"Revocation certificate: back up privately; do not publish until revoking.":"Private export: encrypted with the key passphrase, independently of the vault.");
            }
        });
    }

    void createKeyDialog() {
        QDialog dialog(this); dialog.setWindowTitle("Create OpenPGP key"); dialog.setMinimumWidth(560);
        auto* layout=new QVBoxLayout(&dialog); auto* form=new QFormLayout;
        auto* name=new QLineEdit; auto* email=new QLineEdit; auto* comment=new QLineEdit;
        name->setMaxLength(128); email->setMaxLength(254); comment->setMaxLength(256);
        form->addRow("Name or pseudonym",name); form->addRow("Email (optional)",email); form->addRow("Public comment (optional)",comment);
        auto* disclosure=new QLabel("Email and comment are included in public-key exports. Use encrypted vault notes for private information."); disclosure->setWordWrap(true); form->addRow(disclosure);
        auto* algorithm=new QComboBox;
        algorithm->addItem("Ed25519 / Cv25519 (recommended)","cv25519");
        algorithm->addItem("RSA 2048-bit","rsa2048"); algorithm->addItem("RSA 3072-bit","rsa3072"); algorithm->addItem("RSA 4096-bit","rsa4096");
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
        form->addRow("Private-key passphrase",pass); form->addRow("Confirm passphrase",confirm);
        layout->addLayout(form);
        auto* hint=new QLabel("At least 16 characters. This password protects exported private keys too. RSA-1024 and DSA/ElGamal creation are unavailable; import legacy keys instead."); hint->setWordWrap(true); layout->addWidget(hint);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); error->setWordWrap(true); layout->addWidget(error);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel); layout->addWidget(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        connect(buttons,&QDialogButtonBox::accepted,&dialog,[=,&dialog] {
            if(name->text().trimmed().isEmpty()) { error->setText("Enter a name or pseudonym."); return; }
            if(pass->text().toUcs4().size()<16 || pass->text()!=confirm->text()) { error->setText("Use at least 16 characters and matching passphrases."); return; }
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
        QDialog dialog(this); dialog.setWindowTitle("Protect private key"); auto* form=new QFormLayout(&dialog);
        auto* current=new QLineEdit; auto* pass=new QLineEdit; auto* confirm=new QLineEdit;
        for(auto* field : {current,pass,confirm}) { field->setEchoMode(QLineEdit::Password); field->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase); }
        form->addRow("Current passphrase (if protected)",current); form->addRow("New passphrase (16+ characters)",pass); form->addRow("Confirm new passphrase",confirm);
        auto* error=new QLabel; error->setTextFormat(Qt::PlainText); form->addRow(error);
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel); form->addRow(buttons);
        connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
        connect(buttons,&QDialogButtonBox::accepted,&dialog,[=,&dialog] {
            if(pass->text().toUcs4().size()<16 || pass->text()!=confirm->text()) { error->setText("Use at least 16 characters and matching passphrases."); return; }
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
            keys->setRowCount(0);
            for(const auto& entry:data.value("keys").toArray()) {
                const auto key=entry.toObject(); const int row=keys->rowCount(); keys->insertRow(row);
                auto* recipient=new QTableWidgetItem;
                recipient->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
                recipient->setCheckState(Qt::Unchecked); if(!key.value("can_encrypt").toBool()) recipient->setFlags(Qt::NoItemFlags);
                keys->setItem(row,0,recipient);
                QStringList identities; for(const auto& value:key.value("identities").toArray()) identities.append(value.toString());
                keys->setItem(row,1,new QTableWidgetItem(identities.join("; ")));
                keys->setItem(row,2,new QTableWidgetItem(key.value("has_secret").toBool()?"Public + private":"Public only"));
                keys->setItem(row,3,new QTableWidgetItem(key.value("status").toString()));
                auto* fingerprint=new QTableWidgetItem(key.value("fingerprint").toString()); fingerprint->setData(Qt::UserRole+1,key.value("can_sign").toBool());
                QStringList capabilities; for(const auto& value:key.value("capabilities").toArray()) capabilities.append(value.toString());
                const auto expires=key.value("expires_at");
                fingerprint->setData(Qt::UserRole+2,key.value("algorithm").toString()+" • Expires: "+(expires.isNull()?QString("never"):QDateTime::fromSecsSinceEpoch(expires.toInteger(),QTimeZone::UTC).toString(Qt::ISODate))+"\nCapabilities: "+capabilities.join("; "));
                keys->setItem(row,4,fingerprint);
            }
            if(after) after();
        });
    }

    void buildText() {
        auto* page=new QWidget; auto* layout=new QVBoxLayout(page);
        auto* label=new QLabel("Recipients are checked in the key table. Signatures and public exports can link identities. Text is not automatically saved."); label->setWordWrap(true); layout->addWidget(label);
        selectionSummary=new QLabel; selectionSummary->setTextFormat(Qt::PlainText); selectionSummary->setWordWrap(true); layout->addWidget(selectionSummary);
        input=editor("Paste plaintext or an armored OpenPGP message…"); output=editor("Result appears here after authentication succeeds.",true);
        auto* panes=new QSplitter(Qt::Vertical); panes->addWidget(input); panes->addWidget(output); layout->addWidget(panes,1);
        keyPassword=new QLineEdit; keyPassword->setEchoMode(QLineEdit::Password); keyPassword->setPlaceholderText("Private-key passphrase for signing, decryption, or an imported key's revocation certificate"); keyPassword->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText); layout->addWidget(keyPassword);
        auto* actions=new QHBoxLayout;
        for(const auto& name:QStringList{"Encrypt","Decrypt","Sign","Verify"}) {
            auto* button=new QPushButton(name); actions->addWidget(button);
            connect(button,&QPushButton::clicked,this,[this,name] { textAction(name.toLower()); });
        }
        auto* clear=new QPushButton("Clear"); actions->addWidget(clear);
        connect(clear,&QPushButton::clicked,this,[this]{ input->clear(); output->clear(); keyPassword->clear(); });
        layout->addLayout(actions);
        layout->addWidget(new QLabel("Undo history is disabled. Clipboard managers may retain copied text after locking."));
        tabs->addTab(page,"Text");
    }

    void updateSelection() {
        if(!selectionSummary) return;
        QStringList recipients;
        for(int row=0;row<keys->rowCount();++row) {
            if(keys->item(row,0) && keys->item(row,4) && keys->item(row,0)->checkState()==Qt::Checked)
                recipients.append(keys->item(row,4)->text());
        }
        selectionSummary->setText("Recipients: "+(recipients.isEmpty()?QString("none"):recipients.join(", "))
            +"\nSigner: "+(signer.isEmpty()?QString("none"):signer));
    }

    void textAction(const QString& operation, std::function<void()> after = {}) {
        QJsonArray recipients;
        for(int row=0;row<keys->rowCount();++row) if(keys->item(row,0)->checkState()==Qt::Checked) recipients.append(keys->item(row,4)->text());
        QJsonObject fields{{"text",input->toPlainText()},{"password",keyPassword->text()},{"fingerprint",signer},{"recipients",recipients}};
        output->clear(); keyPassword->clear();
        request(operation,fields,[this,operation,after](bool ok,const QJsonObject& data) {
            if(!ok) return;
            output->setPlainText(data.value("text").toString());
            if(operation=="verify" || operation=="decrypt") {
                QStringList signers; for(const auto& fp:data.value("signers").toArray()) signers.append(fp.toString());
                statusBar()->showMessage(signers.isEmpty()?"Decrypted. No signature verified.":"Valid signature: "+signers.join(", ")+" — identity must be checked independently.");
            } else statusBar()->showMessage(operation=="encrypt"?"Encrypted. Recipient identifiers may be visible in the exported message.":"Signed. The signature can identify the signer.");
            if(after) after();
        });
    }

    void buildNotes() {
        auto* page=new QWidget; auto* layout=new QVBoxLayout(page);
        layout->addWidget(new QLabel("Save explicitly before locking. Unsaved edits are discarded."));
        notes=editor("Notes stored inside the encrypted vault…"); layout->addWidget(notes);
        auto* save=new QPushButton("Save encrypted notes"); layout->addWidget(save);
        connect(save,&QPushButton::clicked,this,[this] { request("notes_set",{{"text",notes->toPlainText()}},[this](bool ok,const QJsonObject&) { if(ok) statusBar()->showMessage("Notes saved inside encrypted vault"); }); });
        tabs->addTab(page,"Notes");
    }

    void testCreate() {
        if(!testDirectory.isValid()) { fail("Test directory failed"); return; }
        path->setText(testDirectory.filePath("fixture.pgpcrypt.age")); create->setChecked(true);
        password->setText("disposable Qt fixture passphrase"); confirmation->setText(password->text());
        unlockButton->click();
    }
    void testGenerate() {
        QJsonObject options{{"name","Desktop fixture"},{"email","fixture@example.invalid"},{"algorithm","cv25519"},{"layout","subkeys"},{"signing",true},{"certification",true},{"transport_encryption",true},{"storage_encryption",true},{"expires_at",QJsonValue(QJsonValue::Null)}};
        request("generate",{{"key_options",options},{"password","disposable Qt key passphrase"}},[this](bool ok,const QJsonObject&) {
            if(!ok) return;
            refreshKeys([this] {
                if(keys->rowCount()!=1) { fail("Key table did not populate"); return; }
                keys->item(0,0)->setCheckState(Qt::Checked); keys->selectRow(0);
                testFingerprint=signer=keys->item(0,4)->text();
                tabs->setCurrentIndex(1); input->setPlainText("Qt desktop private fixture");
                textAction("encrypt",[this] {
                    input->setPlainText(output->toPlainText());
                    keyPassword->setText("disposable Qt key passphrase");
                    textAction("decrypt",[this] {
                        if(output->toPlainText()!="Qt desktop private fixture") { fail("Decryption mismatch"); return; }
                        input->setPlainText("Qt signature fixture");
                        keyPassword->setText("disposable Qt key passphrase");
                        textAction("sign",[this] {
                            input->setPlainText(output->toPlainText());
                            textAction("verify",[this] {
                                if(output->toPlainText()!="Qt signature fixture") { fail("Verification mismatch"); return; }
                                request("notes_set",{{"text","encrypted Qt note"}},[this](bool ok,const QJsonObject&) {
                                    if(!ok) return;
                                    request("notes_get",{},[this](bool ok,const QJsonObject& data) {
                                        if(!ok || data.value("text").toString()!="encrypted Qt note") { fail("Notes mismatch"); return; }
                                        tabs->setCurrentIndex(0);
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
            });
        });
    }
};
}

int main(int argc,char** argv) {
    bool child=false,selfTest=false,smoke=false,restartProbe=false;
    QString screenshot;
    for(int i=1;i<argc;++i) {
        const QByteArray argument(argv[i]);
        if(argument=="--session") child=true;
        if(argument=="--self-test") selfTest=child=true;
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
    QApplication app(argc,argv);
    app.setApplicationName("PGPCrypt"); app.setQuitOnLastWindowClosed(true);
    Window window(selfTest,screenshot,restartProbe); window.show();
    if(smoke) window.smoke();
    if(selfTest) QTimer::singleShot(60000,&app,[&]{ std::fputs("Qt desktop self-test timed out\n",stderr); app.exit(1); });
    return app.exec();
}

#include "main.moc"
