#pragma once

// UI-only session diagnostics. Messages come from a closed vocabulary rather
// than worker replies, operation names or user data. Nothing is written to disk.
#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QStringList>
#include <QTableWidget>
#include <QTextBlock>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextDocument>
#include <QVBoxLayout>

enum class ActivityEvent {
    SessionReady,
    OperationComplete,
    EncryptionComplete,
    DecryptionComplete,
    SigningComplete,
    KeyUpdated,
    OperationFailed,
    VerificationPassed,
    VerificationFailed,
    TextLoaded,
    DocumentSaved
};

class SafeActivityLog final : public QPlainTextEdit {
    struct Severity final : QTextBlockUserData {
        explicit Severity(bool isWarning) : warning(isWarning) {}
        bool warning;
    };
    bool warningsOnly_ = false;

    void applyFilter() {
        for (auto block = document()->begin(); block.isValid(); block = block.next()) {
            const auto* severity = dynamic_cast<const Severity*>(block.userData());
            const bool visible = !warningsOnly_ || (severity && severity->warning);
            if (block.isVisible() != visible) {
                block.setVisible(visible);
                block.setLineCount(visible ? 1 : 0);
            }
        }
        document()->markContentsDirty(0, document()->characterCount());
        viewport()->update();
    }

public:
    explicit SafeActivityLog(QWidget* parent = nullptr) : QPlainTextEdit(parent) {
        setObjectName("sessionActivityLog");
        setReadOnly(true);
        setUndoRedoEnabled(false);
        setAcceptDrops(false);
        setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        setLineWrapMode(QPlainTextEdit::WidgetWidth);
        setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        document()->setMaximumBlockCount(200);
        setMinimumHeight(75);
        setMaximumHeight(145);
        setStyleSheet("QPlainTextEdit { background: #101820; color: #d5e6ec; border: 1px solid #40515b; border-radius: 4px; padding: 7px; }");
    }

    void setWarningsOnly(bool enabled) {
        warningsOnly_ = enabled;
        applyFilter();
        verticalScrollBar()->setValue(verticalScrollBar()->maximum());
    }

    bool warningsOnly() const { return warningsOnly_; }

    void record(ActivityEvent event) {
        // Deliberately no overload accepting a QString. In particular, never
        // pass errors, paths, key identities, password roles or IPC op names.
        QString message;
        QColor color("#d5e6ec");
        switch (event) {
        case ActivityEvent::SessionReady:
            message = "READY  Workspace available. Offline session.";
            color = QColor("#9ed7ff");
            break;
        case ActivityEvent::OperationComplete:
            message = "OK     Operation completed.";
            color = QColor("#8de3a0");
            break;
        case ActivityEvent::EncryptionComplete:
            message = "OK     Message encryption completed."; color = QColor("#8de3a0"); break;
        case ActivityEvent::DecryptionComplete:
            message = "OK     Message decryption completed."; color = QColor("#8de3a0"); break;
        case ActivityEvent::SigningComplete:
            message = "OK     Message signing completed."; color = QColor("#8de3a0"); break;
        case ActivityEvent::KeyUpdated:
            message = "OK     Key changes saved."; color = QColor("#8de3a0"); break;
        case ActivityEvent::OperationFailed:
            message = "ERROR  Operation could not be completed.";
            color = QColor("#ff9a9a");
            break;
        case ActivityEvent::VerificationPassed:
            message = "PASS   Signature verification passed.";
            color = QColor("#8de3a0");
            break;
        case ActivityEvent::VerificationFailed:
            message = "FAIL   Signature verification did not pass.";
            color = QColor("#ff9a9a");
            break;
        case ActivityEvent::TextLoaded:
            message = "INFO   Text loaded into the editor.";
            color = QColor("#9ed7ff");
            break;
        case ActivityEvent::DocumentSaved:
            message = "OK     Document saved.";
            color = QColor("#8de3a0");
            break;
        }
        QTextCursor cursor(document());
        cursor.movePosition(QTextCursor::End);
        if (!document()->isEmpty()) cursor.insertBlock();
        QTextCharFormat format;
        format.setForeground(QColor("#8ca4af"));
        cursor.insertText(QDateTime::currentDateTime().toString("HH:mm:ss") + "  ", format);
        format.setForeground(color);
        cursor.insertText(message, format);
        cursor.block().setUserData(new Severity(event == ActivityEvent::OperationFailed
                                               || event == ActivityEvent::VerificationFailed));
        applyFilter();
        setTextCursor(cursor);
        verticalScrollBar()->setValue(verticalScrollBar()->maximum());
    }
};

inline QDialog* showVerificationDialog(QWidget* parent, bool passed,
                                       const QJsonArray& signerDetails,
                                       const QJsonArray& cachedKeys) {
    // An empty result cannot identify an authenticated signer. Never fall back
    // to identities claimed by an unverified message on the failure path.
    const bool verified = passed && !signerDetails.isEmpty();
    auto* dialog = new QDialog(parent);
    dialog->setObjectName("verificationDialog");
    dialog->setWindowTitle("Signature verification");
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModal(false);
    dialog->setProperty("verificationPassed", verified);
    dialog->resize(920, verified ? 390 : 230);
    auto* layout = new QVBoxLayout(dialog);

    auto* result = new QLabel(verified ? "PASSED — valid signature" : "FAILED — signature not validated");
    result->setObjectName("verificationResult");
    result->setTextFormat(Qt::PlainText);
    result->setWordWrap(true);
    result->setStyleSheet(verified ? "font-size: 19px; font-weight: 600; color: #26854a;"
                                  : "font-size: 19px; font-weight: 600; color: #d45858;");
    layout->addWidget(result);

    if (verified) {
        auto* explanation = new QLabel("Compare the authenticated signing certificate with the key stored in this vault:");
        explanation->setTextFormat(Qt::PlainText);
        explanation->setWordWrap(true);
        layout->addWidget(explanation);

        auto* comparison = new QTableWidget(signerDetails.size() * 2, 2, dialog);
        comparison->setObjectName("verificationComparison");
        comparison->setHorizontalHeaderLabels({"Verified signing certificate", "Stored vault certificate"});
        comparison->setEditTriggers(QAbstractItemView::NoEditTriggers);
        comparison->setSelectionMode(QAbstractItemView::SingleSelection);
        comparison->setSelectionBehavior(QAbstractItemView::SelectItems);
        comparison->setAlternatingRowColors(true);
        comparison->setWordWrap(true);
        comparison->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        comparison->horizontalHeader()->setMinimumSectionSize(150);
        comparison->horizontalHeader()->setStretchLastSection(true);
        comparison->setColumnWidth(0,410); comparison->setColumnWidth(1,410);
        comparison->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        comparison->verticalHeader()->setMinimumSectionSize(35);
        QStringList rows;
        int row = 0;
        bool everyStoredMatch = true;
        for (const auto& value : signerDetails) {
            const auto signer = value.toObject();
            const auto fingerprint = signer.value("fingerprint").toString();
            QStringList verifiedIdentities;
            for (const auto& identity : signer.value("identities").toArray()) verifiedIdentities.append(identity.toString());
            const auto verifiedName = verifiedIdentities.isEmpty() ? QString("No current valid identity") : verifiedIdentities.join("\n");
            QJsonObject stored;
            for (const auto& key : cachedKeys) {
                const auto candidate = key.toObject();
                if (!fingerprint.isEmpty() && candidate.value("fingerprint").toString() == fingerprint) {
                    stored = candidate;
                    break;
                }
            }
            everyStoredMatch = everyStoredMatch && !stored.isEmpty();
            QStringList storedIdentities;
            for (const auto& identity : stored.value("identities").toArray()) storedIdentities.append(identity.toString());
            const auto storedName = stored.isEmpty() ? QString("No matching key in the current vault view")
                : storedIdentities.isEmpty() ? QString("No current valid identity") : storedIdentities.join("\n");
            const auto storedFingerprint = stored.isEmpty() ? QString("Not available") : stored.value("fingerprint").toString();
            const auto ordinal = QString::number(row / 2 + 1);
            rows.append("Signer " + ordinal + " · identity");
            rows.append("Signer " + ordinal + " · fingerprint");
            comparison->setItem(row, 0, new QTableWidgetItem(verifiedName));
            comparison->setItem(row, 1, new QTableWidgetItem(storedName));
            comparison->setItem(row + 1, 0, new QTableWidgetItem(fingerprint));
            comparison->setItem(row + 1, 1, new QTableWidgetItem(storedFingerprint));
            for (int column = 0; column < 2; ++column) comparison->item(row + 1, column)->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            row += 2;
        }
        comparison->setVerticalHeaderLabels(rows);
        comparison->resizeRowsToContents();
        comparison->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(comparison, &QWidget::customContextMenuRequested, dialog, [comparison](const QPoint& point) {
            auto* item = comparison->itemAt(point);
            if (!item) return;
            QMenu menu;
            auto* copyValue = menu.addAction("Copy value");
            auto* copyBoth = menu.addAction("Copy both columns");
            const auto selected = menu.exec(comparison->viewport()->mapToGlobal(point));
            if (selected == copyValue) QApplication::clipboard()->setText(item->text());
            else if (selected == copyBoth) {
                QStringList lines;
                for (int index = 0; index < comparison->rowCount(); ++index)
                    lines.append(comparison->verticalHeaderItem(index)->text() + "\t" + comparison->item(index, 0)->text() + "\t" + comparison->item(index, 1)->text());
                QApplication::clipboard()->setText(lines.join("\n"));
            }
        });
        layout->addWidget(comparison, 1);
        auto* match = new QLabel(everyStoredMatch ? "Full fingerprints match the corresponding stored certificates."
                                                 : "A stored certificate is unavailable in the current vault view.");
        match->setTextFormat(Qt::PlainText);
        match->setWordWrap(true);
        layout->addWidget(match);
    } else {
        auto* failure = new QLabel("No authenticated signer matched this message. The text may have changed, a key may be missing, or the signature may be unsupported.");
        failure->setTextFormat(Qt::PlainText);
        failure->setWordWrap(true);
        layout->addWidget(failure);
    }

    auto* trust = new QLabel("A valid signature does not prove a person's real-world identity. Confirm the full fingerprint through an independent trusted channel.");
    trust->setTextFormat(Qt::PlainText);
    trust->setWordWrap(true);
    layout->addWidget(trust);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    QObject::connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
    layout->addWidget(buttons);
    dialog->show();
    return dialog;
}
