import torch
from torch_geometric.loader import DataLoader
from networks import Net
from dataset import MyDataset
import torch.nn.functional as F
import argparse
import os
from torch.utils.data import random_split
import torchmetrics
import matplotlib.pyplot as plt
from  sklearn.metrics import  roc_curve


parser = argparse.ArgumentParser()

parser.add_argument('--seed', type=int, default=888,
                    help='seed')
parser.add_argument('--batch_size', type=int, default=128,
                    help='batch size')
parser.add_argument('--lr', type=float, default=0.0005,
                    help='learning rate')
parser.add_argument('--weight_decay', type=float, default=0.0001,
                    help='weight decay')
parser.add_argument('--nhid', type=int, default=64,
                    help='hidden size')
parser.add_argument('--pooling_ratio', type=float, default=0.7,
                    help='pooling ratio')
parser.add_argument('--dropout_ratio', type=float, default=0.5,
                    help='dropout ratio')
parser.add_argument('--dataset', type=str, default='MalDroid2020',
                    help='name of dataset')
parser.add_argument('--epochs', type=int, default=10000,
                    help='maximum number of epochs')
parser.add_argument('--patience', type=int, default=50,
                    help='patience for earlystopping')
parser.add_argument('--pooling_layer_type', type=str, default='GCNConv',
                   help='DD/PROTEINS/NCI1/NCI109/Mutagenicity')

args=parser.parse_args()
args.device='cpu'
torch.manual_seed(args.seed)
if torch.cuda.is_available():
    torch.cuda.manual_seed(args.seed)
    args.device = 'cuda:0'
dataset=MyDataset("../dataset",name=args.dataset,use_node_attr=True)
args.num_classes=dataset.num_classes
args.num_features=dataset.num_features

print("数据集名称: "+args.dataset)
print("分类个数："+str(args.num_classes))
print("初始特征维度："+str(args.num_features))
num_training = int(len(dataset)*0.6)
num_val = int(len(dataset)*0.2)
num_test = len(dataset) - (num_training+num_val)
print("训练集大小："+str(num_training))
print("验证集大小："+str(num_val))
print("测试集大小："+str(num_test))

training_set, validation_set, test_set = random_split(dataset, [num_training, num_val, num_test])



train_loader = DataLoader(training_set, batch_size=args.batch_size, shuffle=True)
val_loader = DataLoader(validation_set,batch_size=args.batch_size,shuffle=False)
test_loader = DataLoader(test_set,batch_size=1,shuffle=False)
model = Net(args).to(args.device)
optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)





def test(model,loader):
    test_acc=torchmetrics.Accuracy()
    test_precision=torchmetrics.Precision(average='none',num_classes=2)
    test_recall = torchmetrics.Recall(average='none', num_classes=2)
    test_F1=torchmetrics.F1(average='none',num_classes=2)
    test_roc=torchmetrics.ROC(pos_label=1)
    model.eval()
    correct = 0.
    loss = 0.
    for data in loader:
        data = data.to(args.device)
        out = model(data)

        pred = out.max(dim=1)[1]
        correct += pred.eq(data.y).sum().item()
        loss += F.nll_loss(out,data.y,reduction='sum').item()
        test_acc(pred,data.y)
        test_precision(pred,data.y)
        test_recall(pred,data.y)
        test_F1(pred,data.y)
        test_roc(pred,data.y)

    total_acc=test_acc.compute()
    total_precison=test_precision.compute()
    total_recall=test_recall.compute()
    total_F1=test_F1.compute()
    fpr,tpr,thresholds=test_roc.compute()


    #Reset metric states after each epoch
    test_acc.reset()
    test_precision.reset()
    test_recall.reset()
    test_F1.reset()

    return loss / len(loader.dataset),total_acc,total_precison,total_recall,total_F1,fpr


min_loss = 1e10
patience = 0

for epoch in range(args.epochs):
    model.train()
    for i, data in enumerate(train_loader):
        data = data.to(args.device)
        batch = data.batch
        l = batch.size()[0] - 1
        out = model(data)
        loss = F.nll_loss(out, data.y)
        print("Training loss:{}".format(loss.item()))
        loss.backward()
        optimizer.step()
        optimizer.zero_grad()
    val_loss,val_acc,val_precision,val_recall ,val_F1,val_fpr= test(model,val_loader)
    print("Validation loss:{}\taccuracy:{}\tprecision:{}\trecall:{}\tFPR:{}\tF1_Socre:{}".format(val_loss, val_acc,val_precision,val_recall,val_fpr,val_F1))
    if val_loss < min_loss:
        torch.save(model.state_dict(),'latest.pth')
        print("Model saved at epoch{}".format(epoch))
        min_loss = val_loss
        patience = 0
    else:
        patience += 1
    if patience > args.patience:
        break

model = Net(args).to(args.device)
model.load_state_dict(torch.load('latest.pth'))
test_loss,test_acc,test_precision,test_recall,test_F1,test_fpr= test(model,test_loader)
print("Test accuarcy:"+str(test_acc))
print("Test precison:"+str(test_precision))
print("Test recall:"+str(test_recall))
print("Test FPR:"+str(test_fpr))
print("Test F1:"+str(test_F1))

fpr=test_fpr
tpr=test_recall
plt.plot(fpr,tpr,label=None)
plt.plot([0,1],[0,1],'k--')
plt.axis([0,1,0,1])
plt.xlabel('False Postive Rate')
plt.ylabel('True Postive Rate')
plt.show()



