#pragma once
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSet>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>
#include <functional>

inline QJsonObject workflowStep(const QJsonValue& value) {
    return value.isString()?QJsonObject{{"operation",value.toString()},{"selection","notepad"},{"fingerprints",QJsonArray()},{"require_all_signers",false}}:value.toObject();
}
inline QString workflowOperation(const QJsonValue& value) {return workflowStep(value).value("operation").toString();}

class WorkflowEditor final : public QWidget {
    QListWidget* presets;
    QLineEdit *name,*pattern;
    QTableWidget* steps;
    QWidget* draft;
    QLabel* state;
    QJsonArray keys;
    bool loading=false,dirty=false;
    static QString identity(const QJsonObject& key) {const auto ids=key.value("identities").toArray(); return ids.isEmpty()?QString("No current identity"):ids.first().toString();}
    QJsonArray rowKeys(int row) const {return steps->cellWidget(row,2)->property("fingerprints").toJsonArray();}
    QJsonArray sequence() const {
        QJsonArray result;
        for(int row=0;row<steps->rowCount();++row) {
            const auto op=qobject_cast<QComboBox*>(steps->cellWidget(row,0))->currentData().toString();
            const auto mode=qobject_cast<QComboBox*>(steps->cellWidget(row,1))->currentData().toString();
            result.append(QJsonObject{{"operation",op},{"selection",mode},{"fingerprints",mode=="keys"?rowKeys(row):QJsonArray()},{"require_all_signers",op=="verify" && mode=="keys" && qobject_cast<QCheckBox*>(steps->cellWidget(row,3))->isChecked()}});
        }
        return result;
    }
    void saveDraft() {
        if(loading || !presets->currentItem()) return;
        auto* item=presets->currentItem(); auto value=item->data(Qt::UserRole).toJsonObject(); value.insert("name",name->text().trimmed()); value.insert("output_pattern",pattern->text()); value.insert("steps",sequence()); item->setData(Qt::UserRole,value); item->setText(name->text().trimmed().isEmpty()?"Unnamed workflow":name->text().trimmed()); dirty=true;state->setText("Unsaved workflow changes");
    }
    void rowState(int row) {
        const auto op=qobject_cast<QComboBox*>(steps->cellWidget(row,0))->currentData().toString(); const bool explicitKeys=qobject_cast<QComboBox*>(steps->cellWidget(row,1))->currentData().toString()=="keys";
        auto* choose=qobject_cast<QPushButton*>(steps->cellWidget(row,2)); choose->setEnabled(explicitKeys); const auto selected=rowKeys(row);choose->setText(explicitKeys?(selected.isEmpty()?"Choose keys…":QString::number(selected.size())+" key(s)…"):"Use Notepad selection");
        QStringList labels;for(const auto& fp:selected) {QString label=fp.toString();for(const auto& value:keys) if(value.toObject().value("fingerprint")==fp) {label=identity(value.toObject())+"\n"+fp.toString();break;}labels.append(label);}choose->setToolTip(labels.join("\n\n"));
        auto* required=qobject_cast<QCheckBox*>(steps->cellWidget(row,3));required->setEnabled(op=="verify" && explicitKeys);
    }
    void chooseKeys(int row) {
        const auto op=qobject_cast<QComboBox*>(steps->cellWidget(row,0))->currentData().toString(); const auto selected=rowKeys(row);
        QDialog dialog(this);dialog.setWindowTitle("Keys for this "+op+" step");dialog.resize(780,500);auto* layout=new QVBoxLayout(&dialog);
        auto* hint=new QLabel(op=="sign"?"Every selected key signs the same message. Protected keys are unlocked individually.":op=="encrypt"?"Encrypt for every selected recipient; any matching recipient can decrypt.":op=="decrypt"?"Try only these private keys. Embedded signatures are still checked against public keys in the vault.":"Only these certificates may validate the signature. Enable Require all to require every selected signer.");hint->setWordWrap(true);layout->addWidget(hint);
        auto* search=new QLineEdit;search->setPlaceholderText("Filter name or full fingerprint…");layout->addWidget(search);auto* list=new QListWidget;layout->addWidget(list,1);
        for(const auto& value:keys) {const auto key=value.toObject();const bool usable=op=="sign"?key.value("can_sign").toBool():op=="encrypt"?key.value("can_encrypt").toBool():op=="decrypt"?key.value("has_secret").toBool():true;const auto fp=key.value("fingerprint").toString();auto* item=new QListWidgetItem(identity(key)+"\n"+fp+"   "+key.value("status").toString(),list);item->setData(Qt::UserRole,fp);item->setData(Qt::UserRole+1,usable);item->setFlags(item->flags()|Qt::ItemIsUserCheckable);if(!usable)item->setText(item->text()+" — unavailable for this operation");item->setCheckState(selected.contains(fp)?Qt::Checked:Qt::Unchecked);}
        connect(search,&QLineEdit::textChanged,&dialog,[list](const QString& query){for(int i=0;i<list->count();++i) list->item(i)->setHidden(!list->item(i)->text().contains(query,Qt::CaseInsensitive));});
        auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);layout->addWidget(buttons);connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);connect(buttons,&QDialogButtonBox::accepted,&dialog,[&]{int count=0;for(int i=0;i<list->count();++i) if(list->item(i)->checkState()==Qt::Checked) {if(!list->item(i)->data(Qt::UserRole+1).toBool()){QMessageBox::warning(&dialog,"Choose usable keys","Uncheck unavailable keys, then choose usable replacements.");return;}++count;}if(count<1 || count>16) {QMessageBox::warning(&dialog,"Choose keys","Select 1–16 usable keys.");return;}dialog.accept();});
        if(dialog.exec()!=QDialog::Accepted) return;
        QJsonArray result;for(int i=0;i<list->count();++i) if(list->item(i)->checkState()==Qt::Checked) result.append(list->item(i)->data(Qt::UserRole).toString());steps->cellWidget(row,2)->setProperty("fingerprints",result);rowState(row);saveDraft();
    }
    void loadSteps(const QJsonArray& values) {
        const bool previous=loading;loading=true;steps->setRowCount(0);
        for(const auto& value:values) {const auto step=workflowStep(value);const int row=steps->rowCount();steps->insertRow(row);auto* action=new QComboBox;for(const auto& op:QStringList{"sign","verify","encrypt","decrypt"}) action->addItem(op[0].toUpper()+op.mid(1),op);action->setCurrentIndex(qMax(0,action->findData(step.value("operation").toString())));steps->setCellWidget(row,0,action);auto* selection=new QComboBox;selection->addItem("Notepad selection","notepad");selection->addItem("Choose specific keys","keys");selection->setCurrentIndex(qMax(0,selection->findData(step.value("selection").toString("notepad"))));steps->setCellWidget(row,1,selection);auto* choose=new QPushButton;choose->setProperty("fingerprints",step.value("fingerprints").toArray());steps->setCellWidget(row,2,choose);auto* required=new QCheckBox("Require all");required->setToolTip("Verification must contain a valid signature from every selected key.");required->setChecked(step.value("require_all_signers").toBool());steps->setCellWidget(row,3,required);steps->setRowHeight(row,38);rowState(row);
            connect(action,&QComboBox::currentIndexChanged,this,[this,row]{rowState(row);saveDraft();});connect(selection,&QComboBox::currentIndexChanged,this,[this,row]{rowState(row);saveDraft();});connect(choose,&QPushButton::clicked,this,[this,row]{chooseKeys(row);});connect(required,&QCheckBox::toggled,this,[this]{saveDraft();});
        }loading=previous;
    }
public:
    std::function<void(const QJsonArray&)> onSave;
    explicit WorkflowEditor(QWidget* parent=nullptr):QWidget(parent) {
        setObjectName("workflowEditor");auto* layout=new QVBoxLayout(this);layout->setContentsMargins(0,0,0,0);auto* hint=new QLabel("Build ordered steps with separate signers, recipients or decryption/verification keys. Explicit keys can come from any identity. Run manually from Notepad or choose a batch of files. Passwords and file paths are never stored in workflows.");hint->setWordWrap(true);layout->addWidget(hint);
        auto* splitter=new QSplitter;presets=new QListWidget;presets->setObjectName("automationPresets");presets->setMinimumWidth(160);splitter->addWidget(presets);draft=new QWidget;auto* body=new QVBoxLayout(draft);auto* form=new QFormLayout;name=new QLineEdit;name->setObjectName("automationName");name->setMaxLength(80);pattern=new QLineEdit;pattern->setObjectName("automationPattern");pattern->setMaxLength(120);form->addRow("Workflow name",name);form->addRow("Batch output names",pattern);body->addLayout(form);auto* tokens=new QLabel("Filename tokens: {stem}, {name}, {ext}, {index}, {workflow}. Preview and edit every destination before running.");tokens->setWordWrap(true);body->addWidget(tokens);
        steps=new QTableWidget(0,4);steps->setObjectName("automationSteps");steps->setHorizontalHeaderLabels({"Operation","Key selection","Keys for this step","Verification"});steps->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);steps->horizontalHeader()->setStretchLastSection(true);steps->setColumnWidth(0,100);steps->setColumnWidth(1,165);steps->setColumnWidth(2,180);steps->setSelectionBehavior(QAbstractItemView::SelectRows);body->addWidget(steps,1);
        auto* actions=new QHBoxLayout;auto* addStep=new QPushButton("Add step");auto* removeStep=new QPushButton("Remove step");auto* up=new QPushButton("Move up");auto* down=new QPushButton("Move down");for(auto* button:{addStep,removeStep,up,down}) actions->addWidget(button);body->addLayout(actions);splitter->addWidget(draft);splitter->setStretchFactor(1,3);layout->addWidget(splitter,1);
        auto* footer=new QHBoxLayout;auto* add=new QPushButton("New workflow");auto* remove=new QPushButton("Delete selected");auto* save=new QPushButton("Save workflows");save->setObjectName("saveWorkflows");state=new QLabel("Workflows are saved inside this vault.");footer->addWidget(add);footer->addWidget(remove);footer->addWidget(state,1);footer->addWidget(save);layout->addLayout(footer);
        connect(presets,&QListWidget::currentItemChanged,this,[this](QListWidgetItem* item,QListWidgetItem*){loading=true;name->clear();pattern->clear();if(item) {const auto value=item->data(Qt::UserRole).toJsonObject();name->setText(value.value("name").toString());pattern->setText(value.value("output_pattern").toString("{stem}-{index}.processed"));loadSteps(value.value("steps").toArray());}else loadSteps({});draft->setEnabled(item!=nullptr);loading=false;});
        connect(name,&QLineEdit::textChanged,this,[this]{saveDraft();});connect(pattern,&QLineEdit::textChanged,this,[this]{saveDraft();});
        connect(addStep,&QPushButton::clicked,this,[this]{auto values=sequence();if(values.size()>=32)return;values.append("encrypt");loadSteps(values);steps->selectRow(steps->rowCount()-1);saveDraft();});connect(removeStep,&QPushButton::clicked,this,[this]{auto values=sequence();const int row=steps->currentRow();if(row<0)return;values.removeAt(row);loadSteps(values);saveDraft();});
        auto move=[this](int delta){auto values=sequence();const int row=steps->currentRow(),target=row+delta;if(row<0||target<0||target>=values.size())return;const auto item=values.takeAt(row);values.insert(target,item);loadSteps(values);steps->selectRow(target);saveDraft();};connect(up,&QPushButton::clicked,this,[move]{move(-1);});connect(down,&QPushButton::clicked,this,[move]{move(1);});
        connect(add,&QPushButton::clicked,this,[this]{if(presets->count()>=32)return;auto* item=new QListWidgetItem("New workflow");item->setData(Qt::UserRole,QJsonObject{{"name","New workflow"},{"steps",QJsonArray{"sign","encrypt"}},{"output_pattern","{stem}-{index}.asc"}});presets->addItem(item);presets->setCurrentItem(item);name->setFocus();name->selectAll();saveDraft();});connect(remove,&QPushButton::clicked,this,[this]{delete presets->takeItem(presets->currentRow());dirty=true;state->setText("Unsaved workflow changes");});
        connect(save,&QPushButton::clicked,this,[this]{saveDraft();if(onSave) onSave(values());});draft->setEnabled(false);
    }
    QJsonArray values() const {QJsonArray result;for(int i=0;i<presets->count();++i)result.append(presets->item(i)->data(Qt::UserRole).toJsonObject());return result;}
    void setKeys(const QJsonArray& value) {keys=value;for(int row=0;row<steps->rowCount();++row)rowState(row);}
    void load(const QJsonArray& values,bool force=false) {if(dirty&&!force)return;const auto selected=presets->currentRow();loading=true;presets->clear();for(const auto& value:values){auto* item=new QListWidgetItem(value.toObject().value("name").toString());item->setData(Qt::UserRole,value.toObject());presets->addItem(item);}loading=false;if(presets->count())presets->setCurrentRow(qBound(0,selected,presets->count()-1));dirty=false;state->setText("Workflows saved inside this vault.");}
};
