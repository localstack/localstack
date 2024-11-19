from typing import Final, Optional

from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    VariableDeclarations,
    VariableReference,
)

_VARIABLE_REFERENCE_PARTITION: Final[VariableReference] = "$partition"
_DECLARATION_PARTITION: Final[str] = """
$partition:=function($array,$chunk_size){
  $chunk_size=0?null:
  $chunk_size>=$count($array)?[[$array]]:
  $map(
    [0..$floor($count($array)/$chunk_size)-(1-$count($array)%$chunk_size)],
    function($i){
      $filter($array,function($v,$index){
        $index>=$i*$chunk_size and $index<($i+1)*$chunk_size
      })
    }
  )
};
""".replace("\n", "")

_VARIABLE_REFERENCE_RANGE: Final[VariableReference] = "$range"
_DECLARATION_RANGE: Final[str] = """
$range:=function($first,$last,$step){
  $first>$last and $step>0?[]:
  $first<$last and $step<0?[]:
  $map([0..$floor(($last-$first)/$step)],function($i){
    $first+$i*$step
  })
};
""".replace("\n", "")

# TODO: add support for $hash.
_VARIABLE_REFERENCE_HASH: Final[VariableReference] = "$hash"
_DECLARATION_HASH: Final[VariableReference] = """
$hash:=function($value,$algo){
    "Function $hash is currently not supported"
};
""".replace("\n", "")

_VARIABLE_REFERENCE_RANDOMSEEDED: Final[VariableReference] = "$randomSeeded"
_DECLARATION_RANDOMSEEDED: Final[str] = """
$randomSeeded:=function($seed){
    ($seed*9301+49297)%233280/233280
};
"""

# TODO: add support for $uuid
_VARIABLE_REFERENCE_UUID: Final[VariableReference] = "$uuid"
_DECLARATION_UUID: Final[str] = """
$uuid:=function(){
    "Function $uuid is currently not supported"
};
"""

_VARIABLE_REFERENCE_PARSE: Final[VariableReference] = "$parse"
_DECLARATION_PARSE: Final[str] = """
$parse:=function($v){
    $eval($v)
};
"""

_DECLARATION_BY_VARIABLE_REFERENCE: Final[dict[VariableReference, str]] = {
    _VARIABLE_REFERENCE_PARTITION: _DECLARATION_PARTITION,
    _VARIABLE_REFERENCE_RANGE: _DECLARATION_RANGE,
    _VARIABLE_REFERENCE_HASH: _DECLARATION_HASH,
    _VARIABLE_REFERENCE_RANDOMSEEDED: _DECLARATION_RANDOMSEEDED,
    _VARIABLE_REFERENCE_UUID: _DECLARATION_UUID,
    _VARIABLE_REFERENCE_PARSE: _DECLARATION_PARSE,
}


def get_intrinsic_functions_declarations(
    variable_references: set[VariableReference],
) -> VariableDeclarations:
    declarations: list[str] = list()
    for variable_reference in variable_references:
        declaration: Optional[VariableDeclarations] = _DECLARATION_BY_VARIABLE_REFERENCE.get(
            variable_reference
        )
        if declaration:
            declarations.append(declaration)
    return "".join(declarations)
