from androguard.misc import AnalyzeAPK
import os
from file_path import apk_root

suffix = ".apk"


def Analyze(apk_class, apk):
    """
    :param
    :param
    :return: 分析对象
    """

    path = os.path.join(apk_root, apk_class)
    apk = apk + suffix
    file = os.path.join(path, apk)
    return AnalyzeAPK(file)


def Labeling(Analyze, func, external=0):
    """

    :param Analyze: 分析apk的结果
    :param func:     函数名称
    :param external: 是否external
    :return:
    """
    a, d, dx = Analyze
    # label=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    label = [0, 0, 0, 0, 0, 0, 0]
    op_list = []
    if (external == 1):
        return label
    for method in list(dx.get_methods()):
        m = method.get_method()
        if (str(m) == func):
            for idx, ins in m.get_instructions_idx():
                op_list.append(ins.get_name())
            break
    label = code_7(op_list, label)
    return label


def code_15(op_list, label):
    for op in op_list:
        if 'nop' in op:
            label[0] = 1
            continue
        if 'move' in op:
            label[1] = 1
            continue
        if 'return' in op:
            label[2] = 1
            continue
        if 'monitor' in op:
            label[3] = 1
            continue
        if 'test' in op:
            label[4] = 1
            continue
        if 'new' in op:
            label[5] = 1
            continue
        if 'throw' in op:
            label[6] = 1
            continue
        if 'jump' in op:
            label[7] = 1
            continue
        if 'branch' in op:
            label[8] = 1
            continue
        if 'arrayop' in op:
            label[9] = 1
            continue
        if 'instanceop' in op:
            label[10] = 1
            continue
        if 'staticop' in op:
            label[11] = 1
            continue
        if 'invoke' in op:
            label[12] = 1
            continue
        if 'unop' in op:
            label[13] = 1
            continue
        if 'binop' in op:
            label[14] = 1
    return label


def code_7(op_list, label):
    for op in op_list:
        if 'move' in op:
            label[0] = 1
            continue
        if 'return' in op:
            label[1] = 1
            continue
        if 'goto' in op:
            label[2] = 1
            continue
        if 'if' in op:
            label[3] = 1
            continue
        if 'aget' in op or 'iget' in op:
            label[4] = 1
            continue
        if 'aput' in op or 'iput' in op:
            label[5] = 1
            continue
        if 'invoke' in op or 'range' in op or 'empty' in op or 'invoke' in op:
            label[6] = 1
            continue
    return label
