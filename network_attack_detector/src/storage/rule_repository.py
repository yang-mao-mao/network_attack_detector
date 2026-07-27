from __future__ import annotations
from ..core.models import SignatureRule,BehaviorRule
Rule=SignatureRule|BehaviorRule

#当我们需要从外部模块传入python对象的时候，常常需要新建一个副本，
# 避免与外部共用一个引用，导致数据被意外程序修改，
# 即使是需要对数据加工，也最好是新建副本，再把修改后的副本传出去
#同样的，传出数据也是如此，倘若数据本程序还需要保留，那最好也是传一个副本出去

#创建这个类，用于管理所有的规则，该部分只运行在内存中
class RuleRepository:
    def __init__(self,
                 signature_rules:list[SignatureRule]|None=None,
                 behavior_rules:list[BehaviorRule]|None=None):
        self.signature_rules:list[SignatureRule]=[]
        self.behavior_rules:list[BehaviorRule]=[]
        self.replace_all(signature_rules or [],behavior_rules or [])
        
    def replace_all(self,
                    signature_rules:list[SignatureRule],
                    behavior_rules:list[BehaviorRule]):
        self._ensure_unique_rule_ids([*signature_rules,*behavior_rules])
        #利用到了外部的数据，做个备份
        self.signature_rules=list(signature_rules)
        self.behavior_rules=list(behavior_rules)
    
    def list_signature_rules(self,enabled_only:bool=False):        
        if enabled_only:
            rules=[]
            for rule in self.signature_rules:
                if rule.enabled:
                    rules.append(rule)
            return rules
        return list(self.signature_rules)
    
    def list_behavior_rules(self,enabled_only:bool=False):
        if enabled_only:
            rules=[]
            for rule in self.behavior_rules:
                if rule.enabled:
                    rules.append(rule)
            return rules
        return list(self.behavior_rules)
    
    def list_all(self,enabled_only:bool=False):
        if enabled_only:
            rules=[]
            for rule in self.signature_rules:
                if rule.enabled:
                    rules.append(rule)
            for rule in self.behavior_rules:
                if rule.enabled:
                    rules.append(rule)
            return rules
        return [*self.signature_rules,*self.behavior_rules]
    
    def find_signature_by_id(self,rule_id:str):
        for rule in self.signature_rules:
            if rule.rule_id==rule_id:
                return rule
        return None        
    
    def find_behavior_by_id(self,rule_id:str):
        for rule in self.behavior_rules:
            if rule.rule_id==rule_id:
                return rule
        return None 
    
    def find_by_id(self,rule_id:str):
        return self.find_signature_by_id(rule_id) or self.find_behavior_by_id(rule_id)
    
    def add_signature_rule(self,rule:SignatureRule):
        self._raise_if_rule_exists(rule.rule_id)
        self.signature_rules.append(rule)
        
        
    def add_behavior_rule(self,rule:BehaviorRule):
        self._raise_if_rule_exists(rule.rule_id)
        self.behavior_rules.append(rule)
        
        
    def save_signature_rule(self,rule:SignatureRule):
        index= self._find_rule_index(self.signature_rules,rule.rule_id)
        if index is None:
            self._raise_if_rule_exists(rule.rule_id)
            self.signature_rules.append(rule)
            return
        self.signature_rules[index]=rule
        return
            
            
    def save_behavior_rule(self,rule:BehaviorRule):
        index = self._find_rule_index(self.behavior_rules,rule.rule_id)
        if index is None:
            self._raise_if_rule_exists(rule.rule_id)
            self.behavior_rules.append(rule)
            return
        self.behavior_rules[index]=rule
        return
    
    #根据rulee_id指定，将其enable设置一下
    def set_enabled(self,rule_id:str,enabled:bool):
        rule=self.find_by_id(rule_id)
        if rule is None:
            return False
        rule.enabled=enabled
        return True
        
        
    def enable_rule(self,rule_id:str):
        return self.set_enabled(rule_id,True)
    
    def disable_rule(self,rule_id:str):
        return self.set_enabled(rule_id,False)
    
    def delete(self,rule_id:str):
        signature_index=self._find_rule_index(self.signature_rules,rule_id)
        if signature_index is not None:
            del self.signature_rules[signature_index]
            return True
        behavior_index=self._find_rule_index(self.behavior_rules,rule_id)
        if behavior_index is not None:
            del self.behavior_rules[behavior_index]
            return True
        return False
    
    def clear(self):
        self.signature_rules.clear()
        self.behavior_rules.clear()
        
        
    def count_signature_rules(self, enabled_only: bool = False) -> int:
        """Count signature rules."""
        return len(self.list_signature_rules(enabled_only=enabled_only))

    def count_behavior_rules(self, enabled_only: bool = False) -> int:
        """Count behavior rules."""
        return len(self.list_behavior_rules(enabled_only=enabled_only))

    def count_all(self, enabled_only: bool = False) -> int:
        """Count all rules."""
        return len(self.list_all(enabled_only=enabled_only))   
        
            

     
                    
    def _raise_if_rule_exists(self,rule_id:str):
        if self.find_by_id(rule_id) is not None:
            raise ValueError(f"Rule already exist {rule_id}")
        
        
    @staticmethod
    def _find_rule_index(rules:list[Rule],rule_id:str):
        for index,rule in enumerate(rules):
            if rule.rule_id==rule_id:
                return index
        return None
        
    
            
    @staticmethod#静态方法，不依赖于类实例或类对象，用类名就能直接调用
    def _ensure_unique_rule_ids(rules:list[Rule]):
            seen:set[str]=set()
            for rule in rules:
                if rule.rule_id in seen:
                    raise ValueError(f"Duplicate rule_id:{rule.rule_id}")
                seen.add(rule.rule_id)