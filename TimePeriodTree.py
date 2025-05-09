from datetime import date, timedelta
from typing import Dict, Set, Optional
from charm.toolbox.pairinggroup import PairingGroup

class TimePeriodTreeNode:
    """时间周期树的节点"""
    def __init__(self, level: int, value: str, parent: Optional['TimePeriodTreeNode'] = None):
        """
        :param level: 节点层级（0=根，1=年，2=月，3=日）
        :param value: 节点值（如 "2023", "5", "15"）
        :param parent: 父节点
        """
        self.level = level
        self.value = value
        self.parent = parent
        self.children: Dict[str, TimePeriodTreeNode] = {}  # 子节点 {value: node}
        self.is_leaf = (level == 3)  # 日期节点是叶子节点
        self.node_value = None
        

    def add_child(self, child_value: str) -> 'TimePeriodTreeNode':
        """添加子节点"""
        if child_value in self.children:
            raise ValueError(f"Child {child_value} already exists under {self.value}")
        child_node = TimePeriodTreeNode(
            level=self.level + 1,
            value=child_value,
            parent=self
        )
        self.children[child_value] = child_node
        return child_node

    def get_path(self) -> str:
        """获取从根到当前节点的路径（如 "2023/5/15"）"""
        path = []
        node = self
        while node is not None:
            path.append(node.value)
            node = node.parent
        return "/".join(reversed(path)) if path else "root"


class TimePeriodTree:
    """时间周期树（年-月-日结构）"""
    def __init__(self, depth: int = 3,groupObj: PairingGroup = None, start_year: int = 2000, end_year: int = 2100):
        """
        :param start_year: 起始年份
        :param end_year: 结束年份
        """
        self.group = groupObj
        self.root = TimePeriodTreeNode(level=0, value="root")
        self.years: Dict[int, TimePeriodTreeNode] = {}  # 年份节点 {year: node}
        self.months: Dict[int, Dict[int, TimePeriodTreeNode]] = {}  # 月份节点 {year: {month: node}}
        self.days: Dict[int, Dict[int, Dict[int, TimePeriodTreeNode]]] = {}  # 日期节点 {year: {month: {day: node}}}
        self.tree_depth = depth

        # 初始化树结构
        self._build_tree(start_year, end_year,depth)

    def _build_tree(self, start_year: int, end_year: int,depth: int = 1):
        """构建完整的年-月-日树结构"""
        if depth >= 1:

         for year in range(start_year, end_year + 1):
               year_node = self.root.add_child(str(year))
               self.years[year] = year_node
               # 初始化该年份的月份节点（1-12月）
               if depth >= 2:
                  self.months[year] = {}

                  for month in range(1, 13):
                     month_node = year_node.add_child(f"{month:02d}")  # 格式化为 "01", "02", ..., "12"
                     self.months[year][month] = month_node
                     if depth >= 3:
          
                     # 初始化该月份的日期节点（动态计算天数）
                        self.days[year] = self.days.get(year, {})
                        self.days[year][month] = {}
                        max_days = self._get_days_in_month(year, month)
                        for day in range(1, max_days + 1):
                           day_node = month_node.add_child(f"{day:02d}")  # 格式化为 "01", "02", ..., "31"
                           self.days[year][month][day] = day_node

    @staticmethod
    def _get_days_in_month(year: int, month: int) :
        """获取某年某月的天数"""
        if month == 2:
            return 29 if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0) else 28
        elif month in [4, 6, 9, 11]:
            return 30
        else:
            return 31

   #  def get_node(self, date_str: str) -> Optional[TimePeriodTreeNode]:
   #      """根据日期字符串（如 "2023/5/15"）获取对应的节点"""
   #      try:
   #          year, month, day = map(int, date_str.split("/"))
   #          # print(f"year: {year}, month: {month}, day: {day}")
   #          if year not in self.years:
   #              return None
   #          if month not in self.months[year]:
   #              return None
   #          if day not in self.days[year][month]:
   #              return None
   #          return self.days[year][month][day]
   #      except (ValueError, KeyError):
   #          return None
        
    def get_node(self, date_str: str) -> Optional[TimePeriodTreeNode]:
      """根据日期字符串（如 "2023/05", "2023/05/15"）获取对应的年、月、日节点"""
      try:
         parts = date_str.split("/")
         # 根据路径层级处理不同节点类型
         if len(parts) == 1:  # 年节点（如 "2023"）
               year = int(parts[0])
               return self.years.get(year, None)
         elif len(parts) == 2:  # 月节点（如 "2023/05"）
               year, month = map(int, parts)
               if year not in self.years:
                  return None
               return self.months[year].get(month, None)
         elif len(parts) == 3:  # 日节点（如 "2023/05/15"）
               year, month, day = map(int, parts)
               if year not in self.years or month not in self.months[year]:
                  return None
               return self.days[year][month].get(day, None)
         else:
               return None  # 无效路径
      except (ValueError, KeyError):
         return None


    def get_path(self, date_str: str) -> Optional[str]:
        """获取日期对应的路径（如 "root/2023/05/15"）"""
        node = self.get_node(date_str)
        return node.get_path() if node else None


    def get_minimal_nodes(self,period: tuple):
       start_date, end_date = period
       start_date = self.get_path(start_date)
       end_date = self.get_path(end_date)

       start_parts = start_date.split("/")
       end_parts = end_date.split("/")   
       print(start_parts,end_parts)

       if len(start_parts) == 2:
           start_date = start_date + "/01/01"
       if len(end_parts) == 2:
         #   date = self._get_days_in_month(end_parts[1], end_parts[])
           end_date = end_date + "/12/31"
       if  len(start_parts) == 3:
             start_date = start_date + "/01"
       if len(end_parts) == 3:
           day = self._get_days_in_month(int(end_parts[1]),int( end_parts[2]))
           end_date = f"{end_date}/{day}" 

      #  print(start_date,end_date)
       start_parts = start_date.split("/")
       end_parts = end_date.split("/")   
       print(start_parts,end_parts)

       start_date = date(int(start_parts[1]), int(start_parts[2]), int(start_parts[3]))
       end_date = date(int(end_parts[1]), int(end_parts[2]), int(end_parts[3]))

       def process_year(start, end):
          if start.year != end.year:
                return {}
          if start == date(start.year, 1, 1) and end == date(start.year, 12, 31):
                return {f"root/{start.year}"}
          
          nodes = set()
          current = start
          while current <= end:
                month_start = date(current.year, current.month, 1)
                last_day = get_last_day_of_month(current)
                month_end = date(current.year, current.month, last_day)
                
                if month_start >= start and month_end <= end:
                   nodes.add(f"root/{current.year}/{current.month:02d}")
                   current = month_end + timedelta(days=1)
                else:
                   last = min(month_end, end)
                   temp = current
                   while temp <= last:
                      nodes.add(f"root/{temp.year}/{temp.month:02d}/{temp.day:02d}")
                      temp += timedelta(days=1)
                   current = temp
          print(nodes)
          return nodes
    
       def get_last_day_of_month(d):
          next_month = d.month % 12 + 1
          next_year = d.year + (d.month // 12)
          first_day_next_month = date(next_year, next_month, 1)
          return (first_day_next_month - timedelta(days=1)).day
    
       if start_date > end_date:
          return TypeError('结束日期小于开始日期')
       
       nodes = set()
       start_year = start_date.year
       end_year = end_date.year
    
       if start_year < end_year:
          end_of_start_year = date(start_year, 12, 31)
          nodes.update(process_year(start_date, end_of_start_year))
          
          for year in range(start_year + 1, end_year):
                nodes.add(f"root/{year}")
          
          start_of_end_year = date(end_year, 1, 1)
          nodes.update( process_year(start_of_end_year, end_date))
       else:
          nodes.update( process_year(start_date, end_date))
       
       return nodes

    def check_coverage(self,set_a, set_b):
      def is_covered(a, b):
         # 检查 a 是否是 b 的前缀（覆盖条件）
         return len(a) <= len(b) and a == b[:len(a)]
      
      # 检查集合A是否能覆盖集合B的所有元素
      for b in set_b:
         if not any(is_covered(a, b) for a in set_a):
               return False
      
      # 返回集合B本身（较小精度交集）
      return set(set_b)
    
    def match_sets(self,set_a, set_b):
      results = []
      
      for b_path in set_b:
         b_parts = b_path.split('/')
         best_match = None
         max_depth = -1
         remainder = ''
         
         # 遍历 set_a 中的每个路径，寻找最长前缀匹配
         for a_path in set_a:
               a_parts = a_path.split('/')
               
               # 如果 a 的层级比 b 深，无法成为前缀
               if len(a_parts) > len(b_parts):
                  continue
               
               # 检查是否逐级匹配
               is_prefix = True
               for i in range(len(a_parts)):
                  if a_parts[i] != b_parts[i]:
                     is_prefix = False
                     break
               
               # 更新最长匹配
               if is_prefix and len(a_parts) > max_depth:
                  max_depth = len(a_parts)
                  best_match = a_path
                  remainder = '/'.join(b_parts[len(a_parts):])
         
         # 若无匹配则报错
         if best_match is None:
               raise ValueError(f"No matching prefix found for '{b_path}' in set_a")
         
         results.append((best_match, remainder))
      
      return results




# 示例用法
if __name__ == "__main__":
    # 初始化时间周期树（2000-2100年）
    time_tree = TimePeriodTree(start_year=2000, end_year=2025)

    # 获取某个日期的节点
    node = time_tree.get_node("2023")
    print(f"Node for 2023/5/15: {node.get_path() if node else 'Not found'}")

   #  # 获取所有叶子节点（日期节点）
   #  leaves = time_tree.get_all_leaves()
   #  print(f"Total leaves (dates): {len(leaves)}")

    # 获取某个日期的路径
    path = time_tree.get_path("2023")
    print(f"Path for 2023/5/15: {path}")

   #  dds = time_tree.get_minimal_nodes(date(2020, 3, 6), date(2020, 12, 31))
    dds = time_tree.get_minimal_nodes(('2020', '2020'))
    print(dds)  # 输出: ['root/2020/01', 'root/2020/02', 'root/2020/03', 'root/2020/04', 'root/2020/05', 'root/2020/06', 'root/2020/07', 'root/2020/08', 'root/2020/09', 'root/2020/10', 'root/2020/11', 'root/2020/12']

    set_a = {'root/2019/12/30', 'root/2020'}
    set_b = {'root/2020/12/30'}
    set_c = {'root/2020/03/06', 'root/2020/03/07'}
    
    
    try:
        result = time_tree.check_coverage(set_a, set_b)
        result = time_tree.match_sets(set_a, set_b)
        print("交集结果:", result)  # 输出: {(2020,)}
    except ValueError as e:
        print(e)


