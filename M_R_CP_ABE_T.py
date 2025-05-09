# 导入charm库用于基于配对的加密
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair, GT, extract_key
# 导入secretutil用于访问策略和共享
from charm.toolbox.secretutil import SecretUtil
# 导入随机叶子节点选择
from random import choice

from datetime import timedelta,datetime

from TimePeriodTree import TimePeriodTree

from time import *

import hashlib,re,random

import csv

# 全局调试标志控制打印语句
# debug = False

# 使用二叉树结构管理用户状态和撤销，以实现基于子集覆盖的撤销
class StateInformation:
    def __init__(self, tree_depth:int, groupObj:PairingGroup):
        self.group = groupObj  # 生成群对象
        self.tree_depth = tree_depth # 定义树深度
        self.user_set = set()  # 用户集合
        self.node_set = set() # 节点集合
        self.node_unassignedleafnode = set() # 未分配叶子节点集合
        for i in range(2 ** tree_depth):
            self.node_unassignedleafnode.add(i)  # 初始化所有叶子节点，个数为2 ^ tree_depth
        self.node_value = {}
        self.node_set.add('root')
        for j in range(2 ** tree_depth):
            temp = bin(j)  # 将十进制转化为二进制（如： bin(1) = 0b1 / bin(3) = 0b11 ）
            temp = temp[:2] + (tree_depth - len(temp) + 2) * '0' + temp[2:]  # temp[:2] temp字符串前两个字符 temp[2:] temp 字符串除去前两个字符 统一格式
            for depth in range(1, self.tree_depth + 1):
                self.node_set.add(temp[0:depth + 2])
      #   print(self.node_set)
        self.user_assignment = {}

    def KUNode(self, RL:set):
    
        X = set()

        for GID in RL:
            # 检查用户是否存在
            if GID not in self.user_assignment:
                # 报错
                raise ValueError(f"User {GID} not found")
            # 将用户路径添加到撤销集合
            X.update(self.user_assignment[GID]['path'])
        
        Y = set()
     
        if not RL:
            Y.add('root')
            return Y
        
        if '0b1' not in X:
            Y.add('0b1')
        if '0b0' not in X:
            Y.add('0b0')
        # 迭代撤销路径
        for theta in X:
            # 跳过根节点
            if theta == 'root':
                continue
            # 检查是否是子节点
            if len(theta) < self.tree_depth + 2:
                # 没有撤销添加左节点(左孩子)
                if theta + '0' not in X:
                    Y.add(theta + '0')
                # 没有撤销添加入右节点(右孩子)
                if theta + '1' not in X:
                    Y.add(theta + '1')
        return Y

    # 将新用户分配到叶节点并生成用于加密操作的随机值
    def Update(self, GID:int):
        # 检查是否已注册
        if GID in self.user_set:
            print('Registered GID')
            return
        # 检查叶节点是否可用
        if not self.node_unassignedleafnode:
            # 报错
            raise ValueError("No available leaf nodes")

        self.user_assignment = getattr(self, 'user_assignment', {})
   
        self.user_assignment[GID] = {}
    
        temp = choice(list(self.node_unassignedleafnode))
   
        self.node_unassignedleafnode.remove(temp)
   
        temp = bin(temp)

        temp = temp[:2] + (self.tree_depth - len(temp) + 2) * '0' + temp[2:]
   
        self.user_assignment[GID]['leafnode'] = temp
    
        self.user_assignment[GID]['value'] = self.group.random(ZR)
    
        self.user_assignment[GID]['path'] = set()
 
        self.user_assignment[GID]['path'].add('root')
 
        for depth in range(1, self.tree_depth + 1):
            self.user_assignment[GID]['path'].add(temp[0:depth + 2])

        self.user_set.add(GID)
   
        return self

    def get_path_to_node(self,node:str):
            # 检查节点是否存在
            if node == 'root':
                return {'root'}
            path = set()   # 获取路径
            while node != 'root' and node != '0b':
                path.add(node)
                node = node[:-1]
            path.add('root')
            return path

class CPABE:
    def __init__(self, group_name='SS512'):
        self.group = PairingGroup(group_name)
        self.util = SecretUtil(self.group,verbose=False)

    def setup(self, attributes,U,T):
        """
        实现Setup算法
        :param m: 系统中的属性数量
        :param attributes:系统中的属性集合
        :param U: 用户二叉树深度
        :param T: 时间树深度
        :return: 公钥PK和主密钥MK
        """
        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        miu = self.group.random(ZR)
        self.sTree = StateInformation(U, self.group)
        self.tTree = TimePeriodTree(T,self.group)
        hashAttr = {attr: self.group.hash(attr.encode(), G1) for attr in attributes}
        V_set = {}
        for i in range(T+1):
            V_set[i] = self.group.random(G1)

        PK = {
            'g': g,
            'g_alpha': g ** alpha,
            'g_1_alpha': g ** (1 / alpha),
            'e_g_g_alpha_miu': (pair(g, g) ** alpha) ** miu,
            'hashAttr': hashAttr,
            'V_set': V_set,
        }

        MK = {
            'alpha': alpha,
            'beta': beta,
            'miu': miu,
        }

        return PK, MK

    def keyGen(self, PK, MK, S, uid, u_period=('2000', '2100')):
        """
        实现KeyGen算法
        :param PK: 公钥
        :param MK: 主密钥
        :param S: 用户的属性集
        :param uid: 用户身份
        :param u_period: 用户的有效期
        :return: 用户的解密密钥sk
        """
        S  = {hash_attr(cn) for cn in S}

        # 验证属性集
        if not S.issubset(PK['hashAttr'].keys()):
            raise ValueError("Attributes not in system attribute set")
        
        
        self.sTree.Update(uid)

       
        paths = self.tTree.get_minimal_nodes(u_period)

        p = self.group.random(ZR)
        t = self.group.random(ZR)

        D_AT= {attr: (PK['g_1_alpha'] ** MK['miu']) * (PK['hashAttr'][attr] ** p) for attr in S}

        D2 = PK['g_alpha'] ** p

       # 迭代用户路径节点
        for node in self.sTree.user_assignment[uid]['path']:
           # 检查节点值是否存在
          if self.sTree.node_value.get(node) == None:
              # 随机生成节点值
             self.sTree.node_value[node] = self.group.random(G1)


        D3 = {node: (PK['g'] ** (-(MK['beta']*t + MK['miu'])))  * (self.sTree.node_value[node] ** p)  for node in self.sTree.user_assignment[uid]['path']}
        D4 = PK['g'] ** p
        D0_tau = {}
        D1_tau = {}
        D2_tau = {}
      #   D2_tau = {}
        for i in paths:
            node = '/'.join(i.split('/')[1:])
            if self.tTree.get_node(node).node_value == None:
                self.tTree.get_node(node).node_value = self.group.random(ZR) 
                
            D0_tau[f'root/{node}'] = PK['g'] ** self.tTree.get_node(node).node_value
            
            res = PK['V_set'][0] 
       
            for j,route in enumerate(i.split('/')[1:]):
           
                route = self.group.init(ZR, int(route))
                res *= PK['V_set'][j+1] ** route

            if len(i.split('/')[1:]) < self.tTree.tree_depth:
                D2_tau[f'root/{node}'] = []
                for j in range(len(i.split('/')[1:]),self.tTree.tree_depth):
                    D2_tau[f'root/{node}'].append(PK['V_set'][j+1] ** self.tTree.get_node(node).node_value)

           
            D1_tau[f'root/{node}'] = (res ** self.tTree.get_node(node).node_value) * PK['g'] ** (MK['alpha']*MK['miu'] + MK['beta']*t)

         

        sk = {
            'uid': uid,
            'D_AT': D_AT,
            'D0_tau': D0_tau,
            'D1_tau': D1_tau,
            'D2_tau': D2_tau,
            'D2': D2,
            'D3': D3,
            'D4': D4,
        }

        return sk

    def enc(self, PK, m, access_policy, revoked_list,T_c):
        """
        实现Enc算法
        :param PK: 公钥
        :param m: 待加密的消息
        :param access_policy: 访问策略
        :param revoked_list: 撤销列表
        :param T_c: 时间节点
        :return: 密文cph
        """
        T_c = self.tTree.get_path(T_c)
    
        res = PK['V_set'][0]
        for j,route in enumerate(T_c.split('/')[1:]):
            route = self.group.init(ZR, int(route))
            res *= PK['V_set'][j+1] ** route
        s = self.group.random(ZR)
        res = res ** s
        C0_tau = {T_c: res}

 
        C = m * PK['e_g_g_alpha_miu'] ** s 
        C1 = PK['g'] ** s 
      
        policy = self.util.createPolicy(access_policy)

  
        shares = self.util.calculateSharesDict(s, policy)     

        C2 = {}
        C3 = {}
   
        for i, share in shares.items():
   
            C2[i] = (self.group.hash(i.encode(),G1) ** share) 
            C3[i] = (PK['g_alpha']) ** share
        

        # 模拟子集覆盖技术
        cover_set = self.sTree.KUNode(revoked_list)
    
        C4 = {}
        
        for node in cover_set:

          v_nodes = self.sTree.get_path_to_node(node)
          P_v = 1

          for v_node in v_nodes:
                # 检查节点值是否存在
            # print(v_node)
            if self.sTree.node_value.get(v_node) == None:
                # 随机生成节点值
                self.sTree.node_value[v_node] = self.group.random(G1)
            
            P_v *= self.sTree.node_value[v_node]
       
          C4[node] = P_v  ** s          


        cph = {
            'policy': policy,
            'C': C,
            'C0_tau': C0_tau,
            'C1': C1,
            'C2': C2,
            'C3': C3,
            'C4': C4,
        }

        return cph

    def dec(self, cph, sk,PK):
        """
        实现Dec算法
        :param cph: 密文
        :param sk: 用户的解密密钥
        :return: 解密后的消息m或错误信息
        """
   
        S_s = set(sk['D_AT'].keys())
        S_r = set(cph['C4'].keys())
        T_s = set(sk['D0_tau'].keys())
        T_t = set(cph['C0_tau'].keys())   

    
        coverage = self.tTree.check_coverage(T_s,T_t)

        path = self.sTree.user_assignment[sk['uid']]['path']

        if not coverage:
            raise TypeError('该用户不满足密文所规定的有效访问时间')

        # 判断两种集合是否相交
        if not path.intersection(S_r):
           print("not satisfied")
           raise TypeError('该用户已被撤销')

        pruned_list = self.util.prune(cph['policy'], S_s)

        if pruned_list == False:  # 如果不满足，直接返回False
            raise  TypeError('not satisfied policy')
        
        [(t_node,sub_path)]= self.tTree.match_sets(T_s,coverage)
        print(t_node,sub_path)

        D1_tau = sk['D1_tau'][t_node]

        # level = len(t_node.split('/'))
        
        for i,num in enumerate(sub_path.split('/')):
            if(num == ''):
                break

            D1_tau *=  sk['D2_tau'][t_node][i] ** self.group.init(ZR,int(num))

        K = 1
        omiga = self.util.getCoefficients(cph['policy']) 

        # 验证
        for i in pruned_list:
            attr = i.getAttribute()
            K *= (pair(cph['C3'][attr], sk['D_AT'][attr]) / pair(cph['C2'][attr], sk['D2'])) ** omiga[attr]


        u_node = choice(list(S_r.intersection(path)))

        P_uid = cph['C4'][u_node]
        
        path_u = self.sTree.get_path_to_node(u_node)

        D3_total = self.group.init(ZR, 1)
        
        for node in path_u:
           D3_total *= sk['D3'][node]
       

        # 将路径长度转换为群元素
        path_length = self.group.init(ZR, len(path_u))  

        # 计算群中的逆元素
        inverse_length = self.group.init(ZR, 1) / path_length  


        K *= ((pair(cph['C1'], D3_total) / pair(P_uid, sk['D4'])) ** inverse_length )

        K *= (pair(cph['C1'], D1_tau)/ pair(cph['C0_tau'][list(coverage)[0]], sk['D0_tau'][t_node])) 

        m = cph['C'] / K
        return m

def hash_attr(name):
    # 如果name是中文，则返回其hash值
    if re.search('[\u4e00-\u9fa5]', name):
        # 并且将其中的英文替换为大写
        return hashlib.sha256(name.encode('utf-8')).hexdigest()[:8].upper()
    return name.upper()

def generate_unique_keys(cpabe, PK, MK, num_keys,attributes):
    """
    生成指定数量的唯一密钥
    :param cpabe: CPABE实例（需提前初始化）
    :param PK: 公钥
    :param MK: 主密钥
    :param num_keys: 密钥数量（默认100）
    :return: 生成的密钥列表
    """
    generated_keys = []
    used_uids = set()
    used_periods = set()
    used_attribute_sets = set()

    # 生成100个唯一密钥
    for _ in range(num_keys):
        # 生成唯一uid（假设uid为递增整数）
        uid = len(used_uids) + 1
        while uid in used_uids:
            uid += 1
        used_uids.add(uid)

        # 生成唯一时间周期period
        while True:
            # 随机生成开始日期（2010-01-01至2023-12-31）
            start_year = random.randint(2010, 2023)
            start_month = random.randint(1, 12)
            start_day = random.randint(1, 28)  # 避免闰年问题
            start_date = datetime(start_year, start_month, start_day)
            
            # 随机生成持续时间（1天至3年）
            duration = timedelta(days=random.randint(1, 3*365))
            end_date = start_date + duration
            
            # 格式化日期字符串
            period = (
                start_date.strftime("%Y/%m/%d"),
                end_date.strftime("%Y/%m/%d")
            )
            if period not in used_periods:
                used_periods.add(period)
                break

        # 生成唯一属性集合S
        while True:
            # 随机选择属性数量（1至属性池大小）
            num_attrs = random.randint(1, len(attributes))
            S = frozenset(random.sample(attributes, num_attrs))
            if S not in used_attribute_sets:
                used_attribute_sets.add(S)
                S = set(S)  # 转换回可变的set类型供keyGen使用
                break

        # 调用keyGen生成密钥
        sk = cpabe.keyGen(PK, MK, S, uid, period)
        generated_keys.append(sk)

    return generated_keys

def translate_policy(policy: str, mapping: dict) -> str:
    # 匹配所有连续的汉字
    pattern = re.compile(r"[\u4e00-\u9fff]+")
    return pattern.sub(lambda m: mapping.get(m.group(0), m.group(0)), policy)


def string_to_gt_element(message, group,g):
    # 步骤1: 哈希字符串生成固定长度字节
    hash_bytes = hashlib.sha256(message.encode('utf-8')).digest()

    # 步骤2: 将哈希字节转换为整数
    hash_int = int.from_bytes(hash_bytes, byteorder='big')

    # 步骤3: 获取GT群的阶q，限制整数范围
    q = group.order()  # GT群的阶（通常为大素数）
    m = hash_int % q   # 确保 m ∈ [0, q-1]

    # 步骤4: 获取GT群的生成元gT，计算 gT^m
    gT = g 
    gt_element = gT ** m   # 映射为GT群元素

    return gt_element

if __name__ == "__main__":
   
    attributes = {'ATTR1', 'ATTR2', 'ATTR3', 'ATTR4', 'ATTR5'}

    cpabe = CPABE()

    attr_map = {cn: hash_attr(cn) for cn in attributes}

    attributes_hashed = {hash_attr(cn) for cn in attributes}

    PK, MK = cpabe.setup(attributes_hashed,16,3)

    S = {'ATTR1', 'ATTR2', 'ATTR3'}  # 用户的属性集

    uid = 1

    sk = cpabe.keyGen(PK, MK, S, uid,('2019/03', '2023/04'))  # 用户的解密密钥

    access_policy = '(ATTR1 or ATTR2) and ATTR3 or ATTR4'  # 简单的访问策略

    policy_hashed = translate_policy(access_policy, attr_map)

    revoked_list = []


    msg = "Hello, World!"  # 待加密的消息
    g = cpabe.group.random(GT)
    DK = string_to_gt_element(msg, cpabe.group,g)

    
    cph = cpabe.enc(PK, DK, policy_hashed, revoked_list,'2023/03/14')  # 加密后的密文

    decrypted_message = cpabe.dec(cph, sk,PK)

    if decrypted_message == DK:
        print("解密成功，消息为:", decrypted_message)
    else:
        print("解密失败")


# if __name__ == "__main__":
#     cpabe = CPABE()
#     group = PairingGroup('SS512')
#     g = group.random(GT)

#     # 从 CSV 文件中读取用户数据
#     user_data = []
#     with open('railway_user_dataset.csv', mode='r', encoding='utf-8') as csvfile:
#         reader = csv.DictReader(csvfile)
#         for row in reader:
#             user_data.append(row)

#     # 提取所有属性
#     all_attributes = set()
#     for user in user_data:
#         all_attributes.update(user['权限'].split(','))

#     attr_map = {cn: hash_attr(cn) for cn in all_attributes}
#     attributes_hashed = {hash_attr(cn) for cn in all_attributes}

#     PK, MK = cpabe.setup(attributes_hashed, 16, 3)
#     revoked_list = []

#     for index, user in enumerate(user_data):
#         S = set(user['权限'].split(','))  # 用户的属性集
#         uid = index + 1
#         sk = cpabe.keyGen(PK, MK, S, uid, ('2019/03', '2019/04'))  # 用户的解密密钥

#         access_policy = f"({' or '.join(S)})"  # 简单的访问策略，根据用户属性生成
#         policy_hashed = translate_policy(access_policy, attr_map)

#         msg = f"Message for user {uid}"  # 待加密的消息
#         DK = string_to_gt_element(msg, group, g)

#         cph = cpabe.enc(PK, DK, policy_hashed, revoked_list, '2023/03/14')  # 加密后的密文

#         decrypted_message = cpabe.dec(cph, sk, PK)

#         if decrypted_message == DK:
#             print(f"用户 {uid} 解密成功，消息为:", decrypted_message)
#         else:
#             print(f"用户 {uid} 解密失败")     
 