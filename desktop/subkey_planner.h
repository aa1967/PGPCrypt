#pragma once
#include <QCheckBox>
#include <QComboBox>
#include <QDateTimeEdit>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QTimeZone>

class SubkeyPlanner final : public QWidget {
    QTableWidget* table;
    QPushButton* add;
public:
    explicit SubkeyPlanner(QWidget* parent=nullptr) : QWidget(parent) {
        auto* layout=new QVBoxLayout(this); layout->setContentsMargins(0,0,0,0);
        auto* hint=new QLabel("Add up to 16 rows. Each subkey can have its own purpose, algorithm and expiry. All rows are saved together."); hint->setWordWrap(true); layout->addWidget(hint);
        table=new QTableWidget(0,3); table->setObjectName("subkeyPlan"); table->setHorizontalHeaderLabels({"Purpose","Algorithm","Expiry (UTC)"}); table->setSelectionBehavior(QAbstractItemView::SelectRows); table->setEditTriggers(QAbstractItemView::NoEditTriggers); table->setMinimumHeight(150); table->setMaximumHeight(260); table->horizontalHeader()->setStretchLastSection(true); table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive); table->setColumnWidth(0,150); table->setColumnWidth(1,150); layout->addWidget(table);
        auto* buttons=new QHBoxLayout; add=new QPushButton("Add subkey row"); auto* remove=new QPushButton("Remove selected row"); buttons->addWidget(add); buttons->addWidget(remove); layout->addLayout(buttons);
        connect(add,&QPushButton::clicked,this,[this] {addRow();}); connect(remove,&QPushButton::clicked,this,[this] {if(table->currentRow()>=0) table->removeRow(table->currentRow()); add->setEnabled(table->rowCount()<16);});
    }
    void addRow(const QString& purpose="encrypt",const QString& algorithm="cv25519",qint64 expiry=0) {
        if(table->rowCount()>=16) return;
        const int row=table->rowCount(); table->insertRow(row);
        auto* purposeChoice=new QComboBox; purposeChoice->addItem("Encryption","encrypt"); purposeChoice->addItem("Signing","sign"); purposeChoice->addItem("Authentication","authenticate"); purposeChoice->setCurrentIndex(qMax(0,purposeChoice->findData(purpose))); table->setCellWidget(row,0,purposeChoice);
        auto* algorithmChoice=new QComboBox; algorithmChoice->addItem("Ed25519 / Cv25519","cv25519"); algorithmChoice->addItem("RSA 2048","rsa2048"); algorithmChoice->addItem("RSA 4096","rsa4096"); for(int bits:{256,384,521}) algorithmChoice->addItem("NIST P-"+QString::number(bits),"p"+QString::number(bits)); algorithmChoice->setCurrentIndex(qMax(0,algorithmChoice->findData(algorithm))); table->setCellWidget(row,1,algorithmChoice);
        auto* cell=new QWidget; auto* dates=new QHBoxLayout(cell); dates->setContentsMargins(3,0,3,0); auto* enabled=new QCheckBox; enabled->setToolTip("Set this subkey's expiry"); auto* date=new QDateTimeEdit(expiry>0?QDateTime::fromSecsSinceEpoch(expiry,QTimeZone::UTC):QDateTime::currentDateTimeUtc().addYears(1)); date->setDisplayFormat("yyyy-MM-dd HH:mm"); date->setCalendarPopup(true); date->setObjectName("subkeyExpiry"); enabled->setChecked(expiry>0); date->setEnabled(enabled->isChecked()); connect(enabled,&QCheckBox::toggled,date,&QWidget::setEnabled); dates->addWidget(enabled); dates->addWidget(date,1); table->setCellWidget(row,2,cell); table->setRowHeight(row,36); table->selectRow(row); add->setEnabled(table->rowCount()<16);
    }
    QJsonArray plan() const {
        QJsonArray rows;
        for(int row=0;row<table->rowCount();++row) {
            const auto* purpose=qobject_cast<QComboBox*>(table->cellWidget(row,0)); const auto* algorithm=qobject_cast<QComboBox*>(table->cellWidget(row,1)); auto* cell=table->cellWidget(row,2); auto* enabled=cell->findChild<QCheckBox*>(); auto* date=cell->findChild<QDateTimeEdit*>();
            rows.append(QJsonObject{{"purpose",purpose->currentData().toString()},{"algorithm",algorithm->currentData().toString()},{"expires_at",enabled->isChecked()?QJsonValue(date->dateTime().toSecsSinceEpoch()):QJsonValue(QJsonValue::Null)}});
        }
        return rows;
    }
    QString validation(qint64 primaryExpiry=0) const {
        if(table->rowCount()==0) return "Add at least one subkey row.";
        for(const auto& row:plan()) {
            const auto expiry=row.toObject().value("expires_at");
            if(expiry.isNull() && primaryExpiry>0) return "Give every subkey an expiry within the primary key's lifetime.";
            if(!expiry.isNull() && expiry.toInteger()<=QDateTime::currentSecsSinceEpoch()+60) return "Subkey expiries must be at least a minute in the future.";
            if(!expiry.isNull() && primaryExpiry>0 && expiry.toInteger()>primaryExpiry) return "A subkey cannot outlive its primary key.";
        }
        return {};
    }
};
