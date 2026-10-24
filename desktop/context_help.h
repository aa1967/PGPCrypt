#pragma once
#include <QToolButton>
#include <QWhatsThis>

// Keyboard-accessible help: the same explanation is available on hover or click.
inline QToolButton* contextHelp(QWidget* parent, const QString& explanation) {
    auto* button = new QToolButton(parent);
    button->setText("?");
    button->setAccessibleName("Help");
    button->setToolTip(explanation);
    button->setWhatsThis(explanation);
    button->setAutoRaise(true);
    QObject::connect(button, &QToolButton::clicked, button, [button, explanation] {
        QWhatsThis::showText(button->mapToGlobal(QPoint(0, button->height())), explanation, button);
    });
    return button;
}
