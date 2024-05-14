from typing import Optional, TypedDict

# this is just a recreation of the scaffolded Change type to document some of the meaning behind the fields


class ResourceAttribute(str):
    Properties = "Properties"
    Metadata = "Metadata"
    CreationPolicy = "CreationPolicy"
    UpdatePolicy = "UpdatePolicy"
    DeletionPolicy = "DeletionPolicy"
    UpdateReplacePolicy = "UpdateReplacePolicy"
    Tags = "Tags"


Scope = list[ResourceAttribute]


class ChangeAction(str):
    Add = "Add"
    Modify = "Modify"
    Remove = "Remove"
    Import = "Import"
    Dynamic = "Dynamic"  # exact action for the resource can't be determined


class Replacement(str):
    True_ = "True"
    False_ = "False"
    Conditional = "Conditional"


class ResourceAttribute(str):
    Properties = "Properties"
    Metadata = "Metadata"
    CreationPolicy = "CreationPolicy"
    UpdatePolicy = "UpdatePolicy"
    DeletionPolicy = "DeletionPolicy"
    UpdateReplacePolicy = "UpdateReplacePolicy"
    Tags = "Tags"


Scope = list[ResourceAttribute]


class RequiresRecreation(str):
    Never = "Never"
    Conditionally = "Conditionally"
    Always = "Always"


class ResourceTargetDefinition(TypedDict, total=False):
    Attribute: Optional[ResourceAttribute]
    Name: Optional[str]
    RequiresRecreation: Optional[RequiresRecreation]


class EvaluationType(str):
    Static = "Static"
    Dynamic = "Dynamic"


class ChangeSource(str):
    ResourceReference = "ResourceReference"
    ParameterReference = "ParameterReference"
    ResourceAttribute = "ResourceAttribute"
    DirectModification = "DirectModification"
    Automatic = "Automatic"


class ResourceChangeDetail(TypedDict, total=False):
    Target: Optional[ResourceTargetDefinition]
    Evaluation: Optional[EvaluationType]
    ChangeSource: Optional[ChangeSource]
    CausingEntity: Optional[str]


ResourceChangeDetails = list[ResourceChangeDetail]


class ModuleInfo(TypedDict, total=False):
    """
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/modules.html#module-ref-resources
    https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ModuleInfo.html

     # A concatenated list of the logical IDs of the module or modules containing the resource. Modules are listed starting with the inner-most nested module, and separated by /.
    In the following example, the resource was created from a module, moduleA, that's nested inside a parent module, moduleB.
    moduleA/moduleB

    A concatenated list of the module type or types containing the resource. Module types are listed starting with the inner-most nested module, and separated by /.
    In the following example, the resource was created from a module of type AWS::First::Example::MODULE, that's nested inside a parent module of type AWS::Second::Example::MODULE.
    AWS::First::Example::MODULE/AWS::Second::Example::MODULE
    """

    TypeHierarchy: Optional[str]
    LogicalIdHierarchy: Optional[str]


class ResourceChange(TypedDict, total=False):
    Action: ChangeAction
    LogicalResourceId: str
    PhysicalResourceId: str  # not for Add
    ResourceType: str
    Replacement: Optional[Replacement]  # only for Action == Modify
    Scope: Optional[Scope]  # only for Action == Modify
    Details: Optional[ResourceChangeDetails]
    ChangeSetId: Optional[str]  # only for nested change set
    ModuleInfo: Optional[ModuleInfo]


class ChangeType(str):
    Resource = "Resource"


class Change(TypedDict, total=False):
    Type: Optional[ChangeType]  # always "Resource" at the moment
    HookInvocationCount: Optional[int]  # can be missing as well
    ResourceChange: Optional[ResourceChange]
