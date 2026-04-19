"""
功能：对apk文件使用androguard工具生成call graph(.gml文件)
     生成的callgraph仍然是以良性/恶性

"""

import argparse
import os
from pathlib import Path
from file_path import load_project_paths


# os.chdir(dataset_path)
# print(os.getcwd())


def graph_Generate(source_root, target_root):
    if os.path.exists(source_root):
        os.makedirs(target_root, exist_ok=True)
        for class_folder in os.listdir(source_root):
            print("正在处理的apk标签：", class_folder)
            class_folder_path = os.path.join(source_root, class_folder)
            if class_folder == "benign":
                callgraph_benign_path = os.path.join(target_root, class_folder)
                if not os.path.exists(callgraph_benign_path):
                    os.mkdir(callgraph_benign_path)
                    print("创建" + class_folder + "文件夹")
                Execute(class_folder_path, callgraph_benign_path)

            if class_folder == "malware":
                callgraph_malware_path = os.path.join(target_root, class_folder)
                if not os.path.exists(callgraph_malware_path):
                    os.mkdir(callgraph_malware_path)
                    print("创建" + class_folder + "文件夹")
                Execute(class_folder_path, callgraph_malware_path)
                # callgraph_malware_path= callgraph_root + "\\" + class_folder
                # if not os.path.exists(callgraph_malware_path):
                #     os.mkdir(callgraph_malware_path)
                # for apk_source_folder in os.listdir(class_folder_path):
                #     print("apk来源：" + apk_source_folder)
                #     # 2、把文件名和之前的目录拼接，形成apk文件的绝对路径
                #     apk_soure_folder_path=os.path.join(class_folder_path, apk_source_folder)
                #     # 3、生成存放callgraph的绝对路径，创建apk家族的同名文件夹
                #     callgraph_malware_family_path= callgraph_root + "\\" + class_folder + '\\' + apk_source_folder
                #     if not os.path.exists(callgraph_malware_family_path):
                #         os.mkdir(callgraph_malware_family_path)
                #         print("生成的callgraph目录：",callgraph_malware_family_path)
                #     Execute(apk_soure_folder_path,callgraph_malware_family_path)


def Execute(source_path, target_path):
    # 查找当前目前下所有文件
    apk_list = [filename for filename in os.listdir(source_path)]
    for apk_name in apk_list:
        apk_path = os.path.join(source_path, apk_name)
        # 去除.apk后缀(如果存在)
        apk_name = os.path.splitext(apk_name)[0]
        output_path = os.path.join(target_path, apk_name + '.gml')
        op = 'androguard cg ' + apk_path + ' -o ' + output_path
        print(op)
        # 执行生成call graph命令:androguard cg xx.apk -o ./xx.gml
        os.system(op)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate function call graphs from APK files.")
    parser.add_argument("--apk_root", type=str, default=None, help="APK root path (benign/malware).")
    parser.add_argument("--callgraph_root", type=str, default=None, help="Output callgraph root path.")
    args = parser.parse_args()

    paths = load_project_paths(
        apk_root_value=args.apk_root,
        callgraph_root_value=args.callgraph_root,
    )
    graph_Generate(str(Path(paths.apk_root)), str(Path(paths.callgraph_root)))
