"""
生成raw数据
"""

import os
import networkx as nx
from attributes import betweenness, closeness, pagerank, degree
from numpy import random
import torch
import random
from labels import Analyze, Labeling
from file_path import callgraph_root, data_root, sensitive_API_root

offical_Suspicious_API = []


# 获得节点函数名
def get_func(method):
    s = str(method).replace('<analysis.MethodAnalysis ', '')
    s = s[:-1]
    return s


# 生成子图
def subgraph(G):
    # 敏感API节点
    sus_Nodes = []
    # 子图节点
    sub_Nodes = []
    for node in list(G.nodes):
        for api in offical_Suspicious_API:
            func = get_func(node)
            if func.startswith(api):
                sub_Nodes.append(node)
                sus_Nodes.append(node)
    # 在原图转为无向图筛选
    undirected_G = G.to_undirected()
    for node in sus_Nodes:
        path = nx.shortest_path_length(undirected_G, source=node)
        for adj, dis in path.items():
            if 0 < dis <= 2 and adj not in sub_Nodes:
                sub_Nodes.append(adj)

    SG = nx.subgraph(G, sub_Nodes)
    return SG


def read_sensitive_API():
    with open(sensitive_API_root, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            offical_Suspicious_API.append(line)


class DataLoad(object):
    def __init__(self, source_root, target_root, name):
        self.name = name
        self.node_num = 1
        self.graph_num = 1
        self.path = os.path.join(target_root, self.name)
        self.raw_root = os.path.join(self.path, "raw")
        self.processed_root = os.path.join(self.path, "processed")
        self.file_create()
        self.data_write(source_root)

    def file_create(self):

        read_sensitive_API()

        if not os.path.join(self.path):
            os.makedirs(self.path)

        # 创建raw文件夹及目录下txt文件

        if not os.path.exists(self.raw_root):
            os.makedirs(self.raw_root)
        file = open(self.raw_root + "//" + self.name + "_A.txt", 'w')
        file = open(self.raw_root + "//" + self.name + "_graph_indicator.txt", 'w')
        file = open(self.raw_root + "//" + self.name + "_graph_labels.txt", 'w')
        file = open(self.raw_root + "//" + self.name + "_node_labels.txt", 'w')
        file = open(self.raw_root + '//' + self.name + "_node_attributes.txt", 'w')

        # 创建processed文件夹

        if not os.path.exists(self.processed_root):
            os.makedirs(self.processed_root)

    def data_write(self, source_root):
        if os.path.exists(source_root):
            for class_folder in os.listdir(source_root):
                print("正在处理的apk标签：", class_folder)
                class_folder_path = os.path.join(source_root, class_folder)
                for cg_file in os.listdir(class_folder_path):
                    apk_name = os.path.splitext(cg_file)[0]
                    read_path = os.path.join(class_folder_path, cg_file)
                    G = nx.read_gml(read_path)
                    analyze = Analyze(class_folder, apk_name)
                    # dict_de=degree(FG)
                    # list_bc=betweenness(FG)
                    # dict_cc=closeness(FG)
                    # dict_pg=pagerank(FG)

                    SG = subgraph(G)
                    SG = nx.DiGraph(SG)
                    # 添加ID属性 FG=final graph
                    if nx.number_of_nodes(SG) == 0:
                        continue
                    print('节点个数', nx.number_of_nodes(SG))
                    FG = self.add_id(SG, class_folder)
                    # 构建raw数据
                    self.DS_A(FG)
                    self.DS_graph_indicator(FG)
                    self.DS_graph_labels(class_folder)
                    # self.DS_node_labels(FG)
                    self.DS_node_attributes(FG, analyze)

    def add_id(self, G, graph_label):
        for node in list(G.nodes().items()):
            name = node[0]
            G.add_node(name, node_id=self.node_num)
            self.node_num += 1
            G.add_node(name, graph_id=self.graph_num)
            G.add_node(name, graph_label=graph_label)
        self.graph_num += 1
        return G

    def DS_A(self, G):
        for node in list(G.nodes().items()):
            name = node[0]
            node_id1 = node[1]['node_id']
            for adj in list(G.neighbors(name)):
                node_id2 = G.node[adj]['node_id']
                # print(node_id1,",",node_id2)

                data = open(self.raw_root + "//" + self.name + "_A.txt", 'a')
                print(node_id1, ",", node_id2, file=data)
                data.close()

    def DS_graph_indicator(self, G):
        for node in list(G.nodes().items()):
            graph_id = G.node[node[0]]['graph_id']
            data = open(self.raw_root + "//" + self.name + "_graph_indicator.txt", 'a')
            print(graph_id, file=data)
            data.close()

    def DS_graph_labels(self, graph_label):

        data = open(self.raw_root + "//" + self.name + "_graph_labels.txt", 'a')
        if graph_label == "benign":
            print(0, file=data)
        if graph_label == "malware":
            print(1, file=data)
        data.close()

    def DS_node_labels(self, G):
        for node in list(G.nodes().items()):
            node_label = (random.randint(1, 10))
            data = open(self.raw_root + "//" + self.name + "_node_labels.txt", 'a')
            print(node_label, file=data)
            data.close()

    def random_tensor(self):
        x = torch.randint(5, size=([10]))
        x = x.tolist()
        x = ','.join(str(i) for i in x)
        return x

    def DS_node_attributes(self, G, Analyze):

        for node in list(G.nodes().items()):
            external = G.node[node[0]]['external']
            func = get_func(node[0])
            node_attributes = Labeling(Analyze, func, external)
            node_attributes = ','.join(str(i) for i in node_attributes)
            data = open(self.raw_root + "//" + self.name + "_node_attributes.txt", 'a')
            print(node_attributes, file=data)
            data.close()


if __name__ == '__main__':
    DataLoad(callgraph_root, data_root, "MalDroid2020")
