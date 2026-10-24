#pragma once
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSet>
#include <QVBoxLayout>

inline QJsonArray editWorkflows(QWidget* parent,const QJsonArray& presets,bool* accepted) {
    *accepted=false;
    QDialog dialog(parent); dialog.setWindowTitle("Reusable Notepad workflows"); dialog.resize(720,540); auto* layout=new QVBoxLayout(&dialog);
    auto* hint=new QLabel("Workflows run only when you click Run. Each step consumes the previous result. Keys come from the current Notepad selection; passwords are prompted when needed. Failure stops the workflow. No commands, file writes or background triggers."); hint->setWordWrap(true); layout->addWidget(hint);
    auto* body=new QHBoxLayout; auto* list=new QListWidget; list->setMinimumWidth(190); body->addWidget(list,1); auto* editor=new QWidget; auto* form=new QVBoxLayout(editor); auto* name=new QLineEdit; name->setMaxLength(80); name->setPlaceholderText("Workflow name"); form->addWidget(name); auto* steps=new QListWidget; form->addWidget(steps,1); auto* controls=new QHBoxLayout; auto* operation=new QComboBox; operation->addItems({"Sign","Encrypt","Decrypt","Verify"}); auto* append=new QPushButton("Add step"); auto* removeStep=new QPushButton("Remove step"); controls->addWidget(operation); controls->addWidget(append); controls->addWidget(removeStep); form->addLayout(controls); auto* ordering=new QHBoxLayout; auto* up=new QPushButton("Move up"); auto* down=new QPushButton("Move down"); ordering->addWidget(up); ordering->addWidget(down); form->addLayout(ordering); body->addWidget(editor,2); layout->addLayout(body,1);
    for(const auto& value:presets) {const auto preset=value.toObject(); auto* item=new QListWidgetItem(preset.value("name").toString(),list); item->setData(Qt::UserRole,preset);}
    bool loading=false;
    auto saveDraft=[&] {if(loading || !list->currentItem()) return; QJsonArray sequence; for(int i=0;i<steps->count();++i) sequence.append(steps->item(i)->data(Qt::UserRole).toString()); QJsonObject value{{"name",name->text().trimmed()},{"steps",sequence}}; list->currentItem()->setText(name->text().trimmed().isEmpty()?"Unnamed workflow":name->text().trimmed()); list->currentItem()->setData(Qt::UserRole,value);};
    QObject::connect(list,&QListWidget::currentItemChanged,&dialog,[&](QListWidgetItem* item,QListWidgetItem*) {loading=true; name->clear(); steps->clear(); if(item) {const auto value=item->data(Qt::UserRole).toJsonObject(); name->setText(value.value("name").toString()); for(const auto& step:value.value("steps").toArray()) {auto* entry=new QListWidgetItem(step.toString(),steps); entry->setData(Qt::UserRole,step.toString());}} editor->setEnabled(item!=nullptr); loading=false;});
    QObject::connect(name,&QLineEdit::textChanged,&dialog,[&] {saveDraft();}); QObject::connect(append,&QPushButton::clicked,&dialog,[&] {if(steps->count()>=8) return; auto* item=new QListWidgetItem(operation->currentText(),steps); item->setData(Qt::UserRole,operation->currentText().toLower()); saveDraft();}); QObject::connect(removeStep,&QPushButton::clicked,&dialog,[&] {delete steps->takeItem(steps->currentRow()); saveDraft();});
    auto move=[&](int delta) {const int row=steps->currentRow(),target=row+delta; if(row<0 || target<0 || target>=steps->count()) return; auto* item=steps->takeItem(row); steps->insertItem(target,item); steps->setCurrentRow(target); saveDraft();}; QObject::connect(up,&QPushButton::clicked,&dialog,[&] {move(-1);}); QObject::connect(down,&QPushButton::clicked,&dialog,[&] {move(1);});
    auto* collection=new QHBoxLayout; auto* add=new QPushButton("New workflow"); auto* remove=new QPushButton("Delete selected"); collection->addWidget(add); collection->addWidget(remove); layout->addLayout(collection); QObject::connect(add,&QPushButton::clicked,&dialog,[&] {if(list->count()>=32) return; auto* item=new QListWidgetItem("New workflow",list); item->setData(Qt::UserRole,QJsonObject{{"name","New workflow"},{"steps",QJsonArray{"sign","encrypt"}}}); list->setCurrentItem(item); name->setFocus(); name->selectAll();}); QObject::connect(remove,&QPushButton::clicked,&dialog,[&] {delete list->takeItem(list->currentRow());});
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel); layout->addWidget(buttons); QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject); QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,[&] {saveDraft(); QSet<QString> names; for(int i=0;i<list->count();++i) {const auto value=list->item(i)->data(Qt::UserRole).toJsonObject(); const auto label=value.value("name").toString().trimmed(); const auto sequence=value.value("steps").toArray(); if(label.isEmpty() || names.contains(label.toCaseFolded()) || sequence.isEmpty()) {QMessageBox::warning(&dialog,"Check workflows","Each workflow needs a unique name and 1–8 steps."); return;} names.insert(label.toCaseFolded());} dialog.accept();});
    editor->setEnabled(false); if(list->count()>0) list->setCurrentRow(0);
    if(dialog.exec()!=QDialog::Accepted) return presets;
    QJsonArray result; for(int i=0;i<list->count();++i) result.append(list->item(i)->data(Qt::UserRole).toJsonObject()); *accepted=true; return result;
}
