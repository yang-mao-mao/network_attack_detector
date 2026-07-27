from __future__ import annotations

from ..core.models import BehaviorRule, SignatureRule


# Rule 表示“任意一种规则”：可能是特征规则，也可能是行为规则。
Rule = SignatureRule | BehaviorRule


class RuleRepository:
    """规则仓库练手版。

    练习目标：
    1. 只管理已经加载好的 SignatureRule / BehaviorRule 对象。
    2. 不在这里读取 CSV / JSON。
    3. 不在这里连接 SQLite。
    4. 不在这里校验原始规则字段。
    5. 通过 list / find / add / save / delete / enable 等方法管理内存规则。
    """

    def __init__(
        self,
        signature_rules: list[SignatureRule] | None = None,
        behavior_rules: list[BehaviorRule] | None = None,
    ) -> None:
        """初始化规则仓库。

        你需要做的事：
        1. 创建 self.signature_rules 空列表。
        2. 创建 self.behavior_rules 空列表。
        3. 调用 self.replace_all(...)，把传入的规则放进仓库。
        
        注意：
        调用实例方法时不要手动传 self。
        """
        
        self.signature_rules:list[SignatureRule]=[]
        self.behavior_rules:list[BehaviorRule]=[]
        self.replace_all(signature_rules or [],behavior_rules or [])

    def replace_all(
        self,
        signature_rules: list[SignatureRule],
        behavior_rules: list[BehaviorRule],
    ) -> None:
        """替换仓库里的全部规则。

        你需要做的事：
        1. 检查所有 rule_id 是否唯一。
        2. 用 list(...) 复制外部传入的列表。
        3. 分别赋值给 self.signature_rules 和 self.behavior_rules。
        """
        self._ensure_unique_rule_ids([*signature_rules,*behavior_rules])
        self.signature_rules=list(signature_rules)
        self.behavior_rules=list(behavior_rules)

    def list_signature_rules(self, enabled_only: bool = False) -> list[SignatureRule]:
        """返回特征规则列表。

        enabled_only 为 False：
            返回全部特征规则。

        enabled_only 为 True：
            只返回 enabled == True 的特征规则。

        注意：
        返回列表时建议用 list(...) 或列表推导式，避免直接返回内部列表对象。
        """
        if enabled_only is False:
            return list(self.signature_rules)
        rules=[]
        for rule in self.signature_rules:
            if rule.enabled:
                rules.append(rule)
        return rules
            

    def list_behavior_rules(self, enabled_only: bool = False) -> list[BehaviorRule]:
        """返回行为规则列表。

        enabled_only 为 False：
            返回全部行为规则。

        enabled_only 为 True：
            只返回 enabled == True 的行为规则。
        """
        if enabled_only is False:
            return list(self.behavior_rules)
        rules=[]
        for rule in self.behavior_rules:
            if rule.enabled:
                rules.append(rule)
        return rules

    def list_all(self, enabled_only: bool = False) -> list[Rule]:
        """返回全部规则。

        你需要做的事：
        1. 调用 list_signature_rules(enabled_only=enabled_only)。
        2. 调用 list_behavior_rules(enabled_only=enabled_only)。
        3. 把两个列表合并后返回。
        """
        return [*self.list_behavior_rules(enabled_only),*self.list_signature_rules(enabled_only)]

    def find_signature_by_id(self, rule_id: str) -> SignatureRule | None:
        """按 rule_id 查找特征规则。

        找到：
            返回对应 SignatureRule 对象。

        找不到：
            返回 None。
        """
        for rule in self.signature_rules:
            if rule.rule_id==rule_id:
                return rule
        return None

    def find_behavior_by_id(self, rule_id: str) -> BehaviorRule | None:
        """按 rule_id 查找行为规则。

        找到：
            返回对应 BehaviorRule 对象。

        找不到：
            返回 None。
        """
        for rule in self.behavior_rules:
            if rule.rule_id==rule_id:
                return rule
        return None

    def find_by_id(self, rule_id: str) -> Rule | None:
        """按 rule_id 查找任意规则。

        推荐顺序：
        1. 先查特征规则。
        2. 如果没有，再查行为规则。
        3. 两边都没有，返回 None。
        """
        return self.find_signature_by_id(rule_id) or self.find_behavior_by_id(rule_id)

    def add_signature_rule(self, rule: SignatureRule) -> None:
        """新增一条特征规则。

        你需要做的事：
        1. 检查 rule.rule_id 是否已经存在。
        2. 不存在时 append 到 self.signature_rules。
        3. 已存在时抛 ValueError。
        """
        self._raise_if_rule_exists(rule.rule_id)
        self.signature_rules.append(rule)

    def add_behavior_rule(self, rule: BehaviorRule) -> None:
        """新增一条行为规则。

        逻辑和 add_signature_rule 类似，只是目标列表变成 self.behavior_rules。
        """
        self._raise_if_rule_exists(rule.rule_id)
        self.behavior_rules.append(rule)

    def save_signature_rule(self, rule: SignatureRule) -> None:
        """插入或替换一条特征规则。

        你需要做的事：
        1. 在 self.signature_rules 中查找同 rule_id 的规则位置。
        2. 如果找到了，用新 rule 替换旧 rule。
        3. 如果没找到，还要确认行为规则里没有同 id 规则。
        4. 没有冲突时 append 到 self.signature_rules。
        """
        index=self._find_rule_index(self.signature_rules,rule.rule_id)
        if index is not None:
            self.signature_rules[index]=rule
            return
        self._raise_if_rule_exists(rule.rule_id)
        self.signature_rules.append(rule)
                

    def save_behavior_rule(self, rule: BehaviorRule) -> None:
        """插入或替换一条行为规则。

        逻辑和 save_signature_rule 类似，只是目标列表变成 self.behavior_rules。
        """
        index=self._find_rule_index(self.behavior_rules,rule.rule_id)
        if index is not None:
            self.behavior_rules[index]=rule
            return
        self._raise_if_rule_exists(rule.rule_id)
        self.behavior_rules.append(rule)

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        """启用或禁用一条规则。

        找到规则：
            修改 rule.enabled，返回 True。

        找不到规则：
            返回 False。
        """
        rule=self.find_by_id(rule_id)
        if rule is None:
            return False
        rule.enabled=enabled
        return True

    def enable_rule(self, rule_id: str) -> bool:
        """启用一条规则。

        这里应该调用 set_enabled(rule_id, True)。
        """
        return self.set_enabled(rule_id,True)

    def disable_rule(self, rule_id: str) -> bool:
        """禁用一条规则。

        这里应该调用 set_enabled(rule_id, False)。
        """
        return self.set_enabled(rule_id,False)

    def delete(self, rule_id: str) -> bool:
        """删除一条规则。

        推荐顺序：
        1. 先在 self.signature_rules 中找下标。
        2. 找到就 del，并返回 True。
        3. 否则在 self.behavior_rules 中找下标。
        4. 找到就 del，并返回 True。
        5. 两边都找不到，返回 False。
        """
        index=self._find_rule_index(self.signature_rules,rule_id)
        if index is not None:
            del self.signature_rules[index]
            return True
        index=self._find_rule_index(self.behavior_rules,rule_id)
        if index is not None:
            del self.behavior_rules[index]
            return True
        return False
            

    def clear(self) -> None:
        self.signature_rules.clear()
        self.behavior_rules.clear()
        

    def count_signature_rules(self, enabled_only: bool = False) -> int:
        """统计特征规则数量。

        提示：
        可以复用 list_signature_rules(enabled_only=enabled_only)。
        """
        return len(self.list_signature_rules(enabled_only))
        
    def count_behavior_rules(self, enabled_only: bool = False) -> int:
        """统计行为规则数量。

        提示：
        可以复用 list_behavior_rules(enabled_only=enabled_only)。
        """
        return len(self.list_behavior_rules(enabled_only))

    def count_all(self, enabled_only: bool = False) -> int:
        """统计全部规则数量。

        提示：
        可以复用 list_all(enabled_only=enabled_only)。
        """
        return len(self.list_all(enabled_only))

    def _raise_if_rule_exists(self, rule_id: str) -> None:
        """如果 rule_id 已存在，就抛 ValueError。

        提示：
        可以复用 find_by_id(rule_id)。
        """
        rule=self.find_by_id(rule_id)
        if rule is not None:
            raise ValueError(f"rule_id already existed:{rule_id}")

    @staticmethod
    def _find_rule_index(rules: list[Rule], rule_id: str) -> int | None:
        """在规则列表中查找 rule_id 对应的下标。

        找到：
            返回下标 int。

        找不到：
            返回 None。
        """
        for index,x in enumerate(rules):
            if x.rule_id==rule_id:
                return index
        return None 

    @staticmethod
    def _ensure_unique_rule_ids(rules: list[Rule]) -> None:
        """检查传入规则列表中是否有重复 rule_id。

        你需要做的事：
        1. 创建一个 set 保存已经见过的 rule_id。
        2. 遍历 rules。
        3. 如果 rule.rule_id 已经在 set 中，抛 ValueError。
        4. 否则把 rule.rule_id 加入 set。
        """
        seen=set()
        for rule in rules:
            if rule.rule_id in seen:
                raise ValueError(f"Mutiplicated rule_id : {rule.rule_id}")
            seen.add(rule.rule_id)

