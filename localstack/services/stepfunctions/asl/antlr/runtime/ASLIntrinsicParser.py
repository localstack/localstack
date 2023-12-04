# Generated from /Users/mep/LocalStack/localstack/localstack/services/stepfunctions/asl/antlr/ASLIntrinsicParser.g4 by ANTLR 4.13.1
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,42,123,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,1,0,1,0,
        1,1,1,1,1,1,1,1,1,1,1,2,1,2,1,3,1,3,1,3,1,3,5,3,40,8,3,10,3,12,3,
        43,9,3,1,3,1,3,1,3,1,3,3,3,49,8,3,1,4,1,4,1,4,1,4,1,4,1,4,1,4,3,
        4,58,8,4,1,5,1,5,1,5,1,6,1,6,1,6,1,6,1,6,5,6,68,8,6,10,6,12,6,71,
        9,6,1,7,1,7,3,7,75,8,7,1,8,1,8,1,9,1,9,1,9,1,10,1,10,1,10,1,10,1,
        10,1,10,1,10,1,10,1,10,3,10,91,8,10,1,11,1,11,1,11,1,11,1,11,1,11,
        1,11,1,11,3,11,101,8,11,1,11,1,11,3,11,105,8,11,1,11,1,11,1,11,4,
        11,110,8,11,11,11,12,11,111,5,11,114,8,11,10,11,12,11,117,9,11,1,
        12,1,12,3,12,121,8,12,1,12,0,1,22,13,0,2,4,6,8,10,12,14,16,18,20,
        22,24,0,4,1,0,20,37,1,0,17,18,2,0,9,10,15,15,1,0,13,14,127,0,26,
        1,0,0,0,2,28,1,0,0,0,4,33,1,0,0,0,6,48,1,0,0,0,8,57,1,0,0,0,10,59,
        1,0,0,0,12,62,1,0,0,0,14,74,1,0,0,0,16,76,1,0,0,0,18,78,1,0,0,0,
        20,90,1,0,0,0,22,104,1,0,0,0,24,120,1,0,0,0,26,27,3,2,1,0,27,1,1,
        0,0,0,28,29,5,19,0,0,29,30,5,2,0,0,30,31,3,4,2,0,31,32,3,6,3,0,32,
        3,1,0,0,0,33,34,7,0,0,0,34,5,1,0,0,0,35,36,5,5,0,0,36,41,3,8,4,0,
        37,38,5,4,0,0,38,40,3,8,4,0,39,37,1,0,0,0,40,43,1,0,0,0,41,39,1,
        0,0,0,41,42,1,0,0,0,42,44,1,0,0,0,43,41,1,0,0,0,44,45,5,6,0,0,45,
        49,1,0,0,0,46,47,5,5,0,0,47,49,5,6,0,0,48,35,1,0,0,0,48,46,1,0,0,
        0,49,7,1,0,0,0,50,58,5,38,0,0,51,58,5,39,0,0,52,58,5,40,0,0,53,58,
        7,1,0,0,54,58,3,10,5,0,55,58,3,12,6,0,56,58,3,0,0,0,57,50,1,0,0,
        0,57,51,1,0,0,0,57,52,1,0,0,0,57,53,1,0,0,0,57,54,1,0,0,0,57,55,
        1,0,0,0,57,56,1,0,0,0,58,9,1,0,0,0,59,60,5,1,0,0,60,61,3,12,6,0,
        61,11,1,0,0,0,62,63,5,1,0,0,63,64,5,2,0,0,64,69,3,14,7,0,65,66,5,
        2,0,0,66,68,3,14,7,0,67,65,1,0,0,0,68,71,1,0,0,0,69,67,1,0,0,0,69,
        70,1,0,0,0,70,13,1,0,0,0,71,69,1,0,0,0,72,75,3,16,8,0,73,75,3,18,
        9,0,74,72,1,0,0,0,74,73,1,0,0,0,75,15,1,0,0,0,76,77,3,24,12,0,77,
        17,1,0,0,0,78,79,3,16,8,0,79,80,3,20,10,0,80,19,1,0,0,0,81,82,5,
        7,0,0,82,91,5,8,0,0,83,84,5,7,0,0,84,85,5,39,0,0,85,91,5,8,0,0,86,
        87,5,7,0,0,87,88,3,22,11,0,88,89,5,8,0,0,89,91,1,0,0,0,90,81,1,0,
        0,0,90,83,1,0,0,0,90,86,1,0,0,0,91,21,1,0,0,0,92,93,6,11,-1,0,93,
        105,5,3,0,0,94,95,5,11,0,0,95,100,3,16,8,0,96,97,7,2,0,0,97,101,
        5,39,0,0,98,99,5,16,0,0,99,101,5,38,0,0,100,96,1,0,0,0,100,98,1,
        0,0,0,101,105,1,0,0,0,102,103,5,12,0,0,103,105,5,39,0,0,104,92,1,
        0,0,0,104,94,1,0,0,0,104,102,1,0,0,0,105,115,1,0,0,0,106,109,10,
        1,0,0,107,108,7,3,0,0,108,110,3,22,11,0,109,107,1,0,0,0,110,111,
        1,0,0,0,111,109,1,0,0,0,111,112,1,0,0,0,112,114,1,0,0,0,113,106,
        1,0,0,0,114,117,1,0,0,0,115,113,1,0,0,0,115,116,1,0,0,0,116,23,1,
        0,0,0,117,115,1,0,0,0,118,121,5,41,0,0,119,121,3,4,2,0,120,118,1,
        0,0,0,120,119,1,0,0,0,121,25,1,0,0,0,11,41,48,57,69,74,90,100,104,
        111,115,120
    ]

class ASLIntrinsicParser ( Parser ):

    grammarFileName = "ASLIntrinsicParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'$'", "'.'", "'*'", "','", "'('", "')'", 
                     "'['", "']'", "'<'", "'>'", "'@.'", "'@.length-'", 
                     "'&&'", "'||'", "'=='", "'='", "'true'", "'false'", 
                     "'States'", "'Format'", "'StringToJson'", "'JsonToString'", 
                     "'Array'", "'ArrayPartition'", "'ArrayContains'", "'ArrayRange'", 
                     "'ArrayGetItem'", "'ArrayLength'", "'ArrayUnique'", 
                     "'Base64Encode'", "'Base64Decode'", "'Hash'", "'JsonMerge'", 
                     "'MathRandom'", "'MathAdd'", "'StringSplit'", "'UUID'" ]

    symbolicNames = [ "<INVALID>", "DOLLAR", "DOT", "STAR", "COMMA", "LPAREN", 
                      "RPAREN", "LBRACK", "RBRACK", "LDIAM", "RDIAM", "ATDOT", 
                      "ATDOTLENGTHDASH", "ANDAND", "OROR", "EQEQ", "EQ", 
                      "TRUE", "FALSE", "States", "Format", "StringToJson", 
                      "JsonToString", "Array", "ArrayPartition", "ArrayContains", 
                      "ArrayRange", "ArrayGetItem", "ArrayLength", "ArrayUnique", 
                      "Base64Encode", "Base64Decode", "Hash", "JsonMerge", 
                      "MathRandom", "MathAdd", "StringSplit", "UUID", "STRING", 
                      "INT", "NUMBER", "IDENTIFIER", "WS" ]

    RULE_func_decl = 0
    RULE_states_func_decl = 1
    RULE_state_fun_name = 2
    RULE_func_arg_list = 3
    RULE_func_arg = 4
    RULE_context_path = 5
    RULE_json_path = 6
    RULE_json_path_part = 7
    RULE_json_path_iden = 8
    RULE_json_path_iden_qual = 9
    RULE_json_path_qual = 10
    RULE_json_path_query = 11
    RULE_identifier = 12

    ruleNames =  [ "func_decl", "states_func_decl", "state_fun_name", "func_arg_list", 
                   "func_arg", "context_path", "json_path", "json_path_part", 
                   "json_path_iden", "json_path_iden_qual", "json_path_qual", 
                   "json_path_query", "identifier" ]

    EOF = Token.EOF
    DOLLAR=1
    DOT=2
    STAR=3
    COMMA=4
    LPAREN=5
    RPAREN=6
    LBRACK=7
    RBRACK=8
    LDIAM=9
    RDIAM=10
    ATDOT=11
    ATDOTLENGTHDASH=12
    ANDAND=13
    OROR=14
    EQEQ=15
    EQ=16
    TRUE=17
    FALSE=18
    States=19
    Format=20
    StringToJson=21
    JsonToString=22
    Array=23
    ArrayPartition=24
    ArrayContains=25
    ArrayRange=26
    ArrayGetItem=27
    ArrayLength=28
    ArrayUnique=29
    Base64Encode=30
    Base64Decode=31
    Hash=32
    JsonMerge=33
    MathRandom=34
    MathAdd=35
    StringSplit=36
    UUID=37
    STRING=38
    INT=39
    NUMBER=40
    IDENTIFIER=41
    WS=42

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class Func_declContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def states_func_decl(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.States_func_declContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_func_decl

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_decl" ):
                listener.enterFunc_decl(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_decl" ):
                listener.exitFunc_decl(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_decl" ):
                return visitor.visitFunc_decl(self)
            else:
                return visitor.visitChildren(self)




    def func_decl(self):

        localctx = ASLIntrinsicParser.Func_declContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_func_decl)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 26
            self.states_func_decl()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class States_func_declContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def States(self):
            return self.getToken(ASLIntrinsicParser.States, 0)

        def DOT(self):
            return self.getToken(ASLIntrinsicParser.DOT, 0)

        def state_fun_name(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.State_fun_nameContext,0)


        def func_arg_list(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Func_arg_listContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_states_func_decl

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStates_func_decl" ):
                listener.enterStates_func_decl(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStates_func_decl" ):
                listener.exitStates_func_decl(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStates_func_decl" ):
                return visitor.visitStates_func_decl(self)
            else:
                return visitor.visitChildren(self)




    def states_func_decl(self):

        localctx = ASLIntrinsicParser.States_func_declContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_states_func_decl)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 28
            self.match(ASLIntrinsicParser.States)
            self.state = 29
            self.match(ASLIntrinsicParser.DOT)
            self.state = 30
            self.state_fun_name()
            self.state = 31
            self.func_arg_list()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class State_fun_nameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def Format(self):
            return self.getToken(ASLIntrinsicParser.Format, 0)

        def StringToJson(self):
            return self.getToken(ASLIntrinsicParser.StringToJson, 0)

        def JsonToString(self):
            return self.getToken(ASLIntrinsicParser.JsonToString, 0)

        def Array(self):
            return self.getToken(ASLIntrinsicParser.Array, 0)

        def ArrayPartition(self):
            return self.getToken(ASLIntrinsicParser.ArrayPartition, 0)

        def ArrayContains(self):
            return self.getToken(ASLIntrinsicParser.ArrayContains, 0)

        def ArrayRange(self):
            return self.getToken(ASLIntrinsicParser.ArrayRange, 0)

        def ArrayGetItem(self):
            return self.getToken(ASLIntrinsicParser.ArrayGetItem, 0)

        def ArrayLength(self):
            return self.getToken(ASLIntrinsicParser.ArrayLength, 0)

        def ArrayUnique(self):
            return self.getToken(ASLIntrinsicParser.ArrayUnique, 0)

        def Base64Encode(self):
            return self.getToken(ASLIntrinsicParser.Base64Encode, 0)

        def Base64Decode(self):
            return self.getToken(ASLIntrinsicParser.Base64Decode, 0)

        def Hash(self):
            return self.getToken(ASLIntrinsicParser.Hash, 0)

        def JsonMerge(self):
            return self.getToken(ASLIntrinsicParser.JsonMerge, 0)

        def MathRandom(self):
            return self.getToken(ASLIntrinsicParser.MathRandom, 0)

        def MathAdd(self):
            return self.getToken(ASLIntrinsicParser.MathAdd, 0)

        def StringSplit(self):
            return self.getToken(ASLIntrinsicParser.StringSplit, 0)

        def UUID(self):
            return self.getToken(ASLIntrinsicParser.UUID, 0)

        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_state_fun_name

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_fun_name" ):
                listener.enterState_fun_name(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_fun_name" ):
                listener.exitState_fun_name(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_fun_name" ):
                return visitor.visitState_fun_name(self)
            else:
                return visitor.visitChildren(self)




    def state_fun_name(self):

        localctx = ASLIntrinsicParser.State_fun_nameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_state_fun_name)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 33
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 274876858368) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Func_arg_listContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LPAREN(self):
            return self.getToken(ASLIntrinsicParser.LPAREN, 0)

        def func_arg(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.Func_argContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.Func_argContext,i)


        def RPAREN(self):
            return self.getToken(ASLIntrinsicParser.RPAREN, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(ASLIntrinsicParser.COMMA)
            else:
                return self.getToken(ASLIntrinsicParser.COMMA, i)

        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_func_arg_list

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_list" ):
                listener.enterFunc_arg_list(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_list" ):
                listener.exitFunc_arg_list(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_list" ):
                return visitor.visitFunc_arg_list(self)
            else:
                return visitor.visitChildren(self)




    def func_arg_list(self):

        localctx = ASLIntrinsicParser.Func_arg_listContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_func_arg_list)
        self._la = 0 # Token type
        try:
            self.state = 48
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 35
                self.match(ASLIntrinsicParser.LPAREN)
                self.state = 36
                self.func_arg()
                self.state = 41
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==4:
                    self.state = 37
                    self.match(ASLIntrinsicParser.COMMA)
                    self.state = 38
                    self.func_arg()
                    self.state = 43
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 44
                self.match(ASLIntrinsicParser.RPAREN)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 46
                self.match(ASLIntrinsicParser.LPAREN)
                self.state = 47
                self.match(ASLIntrinsicParser.RPAREN)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Func_argContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_func_arg

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class Func_arg_context_pathContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def context_path(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Context_pathContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_context_path" ):
                listener.enterFunc_arg_context_path(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_context_path" ):
                listener.exitFunc_arg_context_path(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_context_path" ):
                return visitor.visitFunc_arg_context_path(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_floatContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NUMBER(self):
            return self.getToken(ASLIntrinsicParser.NUMBER, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_float" ):
                listener.enterFunc_arg_float(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_float" ):
                listener.exitFunc_arg_float(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_float" ):
                return visitor.visitFunc_arg_float(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_func_declContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def func_decl(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Func_declContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_func_decl" ):
                listener.enterFunc_arg_func_decl(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_func_decl" ):
                listener.exitFunc_arg_func_decl(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_func_decl" ):
                return visitor.visitFunc_arg_func_decl(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_intContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def INT(self):
            return self.getToken(ASLIntrinsicParser.INT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_int" ):
                listener.enterFunc_arg_int(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_int" ):
                listener.exitFunc_arg_int(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_int" ):
                return visitor.visitFunc_arg_int(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_boolContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def TRUE(self):
            return self.getToken(ASLIntrinsicParser.TRUE, 0)
        def FALSE(self):
            return self.getToken(ASLIntrinsicParser.FALSE, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_bool" ):
                listener.enterFunc_arg_bool(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_bool" ):
                listener.exitFunc_arg_bool(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_bool" ):
                return visitor.visitFunc_arg_bool(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_stringContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def STRING(self):
            return self.getToken(ASLIntrinsicParser.STRING, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_string" ):
                listener.enterFunc_arg_string(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_string" ):
                listener.exitFunc_arg_string(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_string" ):
                return visitor.visitFunc_arg_string(self)
            else:
                return visitor.visitChildren(self)


    class Func_arg_json_pathContext(Func_argContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Func_argContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def json_path(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_pathContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunc_arg_json_path" ):
                listener.enterFunc_arg_json_path(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunc_arg_json_path" ):
                listener.exitFunc_arg_json_path(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunc_arg_json_path" ):
                return visitor.visitFunc_arg_json_path(self)
            else:
                return visitor.visitChildren(self)



    def func_arg(self):

        localctx = ASLIntrinsicParser.Func_argContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_func_arg)
        self._la = 0 # Token type
        try:
            self.state = 57
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
            if la_ == 1:
                localctx = ASLIntrinsicParser.Func_arg_stringContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 50
                self.match(ASLIntrinsicParser.STRING)
                pass

            elif la_ == 2:
                localctx = ASLIntrinsicParser.Func_arg_intContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 51
                self.match(ASLIntrinsicParser.INT)
                pass

            elif la_ == 3:
                localctx = ASLIntrinsicParser.Func_arg_floatContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 52
                self.match(ASLIntrinsicParser.NUMBER)
                pass

            elif la_ == 4:
                localctx = ASLIntrinsicParser.Func_arg_boolContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 53
                _la = self._input.LA(1)
                if not(_la==17 or _la==18):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                pass

            elif la_ == 5:
                localctx = ASLIntrinsicParser.Func_arg_context_pathContext(self, localctx)
                self.enterOuterAlt(localctx, 5)
                self.state = 54
                self.context_path()
                pass

            elif la_ == 6:
                localctx = ASLIntrinsicParser.Func_arg_json_pathContext(self, localctx)
                self.enterOuterAlt(localctx, 6)
                self.state = 55
                self.json_path()
                pass

            elif la_ == 7:
                localctx = ASLIntrinsicParser.Func_arg_func_declContext(self, localctx)
                self.enterOuterAlt(localctx, 7)
                self.state = 56
                self.func_decl()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Context_pathContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOLLAR(self):
            return self.getToken(ASLIntrinsicParser.DOLLAR, 0)

        def json_path(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_pathContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_context_path

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterContext_path" ):
                listener.enterContext_path(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitContext_path" ):
                listener.exitContext_path(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitContext_path" ):
                return visitor.visitContext_path(self)
            else:
                return visitor.visitChildren(self)




    def context_path(self):

        localctx = ASLIntrinsicParser.Context_pathContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_context_path)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 59
            self.match(ASLIntrinsicParser.DOLLAR)
            self.state = 60
            self.json_path()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_pathContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOLLAR(self):
            return self.getToken(ASLIntrinsicParser.DOLLAR, 0)

        def DOT(self, i:int=None):
            if i is None:
                return self.getTokens(ASLIntrinsicParser.DOT)
            else:
                return self.getToken(ASLIntrinsicParser.DOT, i)

        def json_path_part(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.Json_path_partContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_partContext,i)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path" ):
                listener.enterJson_path(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path" ):
                listener.exitJson_path(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path" ):
                return visitor.visitJson_path(self)
            else:
                return visitor.visitChildren(self)




    def json_path(self):

        localctx = ASLIntrinsicParser.Json_pathContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_json_path)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 62
            self.match(ASLIntrinsicParser.DOLLAR)
            self.state = 63
            self.match(ASLIntrinsicParser.DOT)
            self.state = 64
            self.json_path_part()
            self.state = 69
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==2:
                self.state = 65
                self.match(ASLIntrinsicParser.DOT)
                self.state = 66
                self.json_path_part()
                self.state = 71
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_path_partContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def json_path_iden(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_idenContext,0)


        def json_path_iden_qual(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_iden_qualContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path_part

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_part" ):
                listener.enterJson_path_part(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_part" ):
                listener.exitJson_path_part(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_part" ):
                return visitor.visitJson_path_part(self)
            else:
                return visitor.visitChildren(self)




    def json_path_part(self):

        localctx = ASLIntrinsicParser.Json_path_partContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_json_path_part)
        try:
            self.state = 74
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,4,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 72
                self.json_path_iden()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 73
                self.json_path_iden_qual()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_path_idenContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.IdentifierContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path_iden

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_iden" ):
                listener.enterJson_path_iden(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_iden" ):
                listener.exitJson_path_iden(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_iden" ):
                return visitor.visitJson_path_iden(self)
            else:
                return visitor.visitChildren(self)




    def json_path_iden(self):

        localctx = ASLIntrinsicParser.Json_path_idenContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_json_path_iden)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 76
            self.identifier()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_path_iden_qualContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def json_path_iden(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_idenContext,0)


        def json_path_qual(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_qualContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path_iden_qual

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_iden_qual" ):
                listener.enterJson_path_iden_qual(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_iden_qual" ):
                listener.exitJson_path_iden_qual(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_iden_qual" ):
                return visitor.visitJson_path_iden_qual(self)
            else:
                return visitor.visitChildren(self)




    def json_path_iden_qual(self):

        localctx = ASLIntrinsicParser.Json_path_iden_qualContext(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_json_path_iden_qual)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 78
            self.json_path_iden()
            self.state = 79
            self.json_path_qual()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_path_qualContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path_qual

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class Json_path_qual_voidContext(Json_path_qualContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_qualContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def LBRACK(self):
            return self.getToken(ASLIntrinsicParser.LBRACK, 0)
        def RBRACK(self):
            return self.getToken(ASLIntrinsicParser.RBRACK, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_qual_void" ):
                listener.enterJson_path_qual_void(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_qual_void" ):
                listener.exitJson_path_qual_void(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_qual_void" ):
                return visitor.visitJson_path_qual_void(self)
            else:
                return visitor.visitChildren(self)


    class Json_path_qual_queryContext(Json_path_qualContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_qualContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def LBRACK(self):
            return self.getToken(ASLIntrinsicParser.LBRACK, 0)
        def json_path_query(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_queryContext,0)

        def RBRACK(self):
            return self.getToken(ASLIntrinsicParser.RBRACK, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_qual_query" ):
                listener.enterJson_path_qual_query(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_qual_query" ):
                listener.exitJson_path_qual_query(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_qual_query" ):
                return visitor.visitJson_path_qual_query(self)
            else:
                return visitor.visitChildren(self)


    class Json_path_qual_idxContext(Json_path_qualContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_qualContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def LBRACK(self):
            return self.getToken(ASLIntrinsicParser.LBRACK, 0)
        def INT(self):
            return self.getToken(ASLIntrinsicParser.INT, 0)
        def RBRACK(self):
            return self.getToken(ASLIntrinsicParser.RBRACK, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_qual_idx" ):
                listener.enterJson_path_qual_idx(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_qual_idx" ):
                listener.exitJson_path_qual_idx(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_qual_idx" ):
                return visitor.visitJson_path_qual_idx(self)
            else:
                return visitor.visitChildren(self)



    def json_path_qual(self):

        localctx = ASLIntrinsicParser.Json_path_qualContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_json_path_qual)
        try:
            self.state = 90
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
            if la_ == 1:
                localctx = ASLIntrinsicParser.Json_path_qual_voidContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 81
                self.match(ASLIntrinsicParser.LBRACK)
                self.state = 82
                self.match(ASLIntrinsicParser.RBRACK)
                pass

            elif la_ == 2:
                localctx = ASLIntrinsicParser.Json_path_qual_idxContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 83
                self.match(ASLIntrinsicParser.LBRACK)
                self.state = 84
                self.match(ASLIntrinsicParser.INT)
                self.state = 85
                self.match(ASLIntrinsicParser.RBRACK)
                pass

            elif la_ == 3:
                localctx = ASLIntrinsicParser.Json_path_qual_queryContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 86
                self.match(ASLIntrinsicParser.LBRACK)
                self.state = 87
                self.json_path_query(0)
                self.state = 88
                self.match(ASLIntrinsicParser.RBRACK)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_path_queryContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_json_path_query

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class Json_path_query_cmpContext(Json_path_queryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_queryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def ATDOT(self):
            return self.getToken(ASLIntrinsicParser.ATDOT, 0)
        def json_path_iden(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_idenContext,0)

        def INT(self):
            return self.getToken(ASLIntrinsicParser.INT, 0)
        def EQ(self):
            return self.getToken(ASLIntrinsicParser.EQ, 0)
        def STRING(self):
            return self.getToken(ASLIntrinsicParser.STRING, 0)
        def LDIAM(self):
            return self.getToken(ASLIntrinsicParser.LDIAM, 0)
        def RDIAM(self):
            return self.getToken(ASLIntrinsicParser.RDIAM, 0)
        def EQEQ(self):
            return self.getToken(ASLIntrinsicParser.EQEQ, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_query_cmp" ):
                listener.enterJson_path_query_cmp(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_query_cmp" ):
                listener.exitJson_path_query_cmp(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_query_cmp" ):
                return visitor.visitJson_path_query_cmp(self)
            else:
                return visitor.visitChildren(self)


    class Json_path_query_lengthContext(Json_path_queryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_queryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def ATDOTLENGTHDASH(self):
            return self.getToken(ASLIntrinsicParser.ATDOTLENGTHDASH, 0)
        def INT(self):
            return self.getToken(ASLIntrinsicParser.INT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_query_length" ):
                listener.enterJson_path_query_length(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_query_length" ):
                listener.exitJson_path_query_length(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_query_length" ):
                return visitor.visitJson_path_query_length(self)
            else:
                return visitor.visitChildren(self)


    class Json_path_query_binaryContext(Json_path_queryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_queryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def json_path_query(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.Json_path_queryContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.Json_path_queryContext,i)

        def ANDAND(self, i:int=None):
            if i is None:
                return self.getTokens(ASLIntrinsicParser.ANDAND)
            else:
                return self.getToken(ASLIntrinsicParser.ANDAND, i)
        def OROR(self, i:int=None):
            if i is None:
                return self.getTokens(ASLIntrinsicParser.OROR)
            else:
                return self.getToken(ASLIntrinsicParser.OROR, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_query_binary" ):
                listener.enterJson_path_query_binary(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_query_binary" ):
                listener.exitJson_path_query_binary(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_query_binary" ):
                return visitor.visitJson_path_query_binary(self)
            else:
                return visitor.visitChildren(self)


    class Json_path_query_starContext(Json_path_queryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a ASLIntrinsicParser.Json_path_queryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def STAR(self):
            return self.getToken(ASLIntrinsicParser.STAR, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_path_query_star" ):
                listener.enterJson_path_query_star(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_path_query_star" ):
                listener.exitJson_path_query_star(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_path_query_star" ):
                return visitor.visitJson_path_query_star(self)
            else:
                return visitor.visitChildren(self)



    def json_path_query(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = ASLIntrinsicParser.Json_path_queryContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 22
        self.enterRecursionRule(localctx, 22, self.RULE_json_path_query, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 104
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [3]:
                localctx = ASLIntrinsicParser.Json_path_query_starContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 93
                self.match(ASLIntrinsicParser.STAR)
                pass
            elif token in [11]:
                localctx = ASLIntrinsicParser.Json_path_query_cmpContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 94
                self.match(ASLIntrinsicParser.ATDOT)
                self.state = 95
                self.json_path_iden()
                self.state = 100
                self._errHandler.sync(self)
                token = self._input.LA(1)
                if token in [9, 10, 15]:
                    self.state = 96
                    _la = self._input.LA(1)
                    if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 34304) != 0)):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()
                    self.state = 97
                    self.match(ASLIntrinsicParser.INT)
                    pass
                elif token in [16]:
                    self.state = 98
                    self.match(ASLIntrinsicParser.EQ)
                    self.state = 99
                    self.match(ASLIntrinsicParser.STRING)
                    pass
                else:
                    raise NoViableAltException(self)

                pass
            elif token in [12]:
                localctx = ASLIntrinsicParser.Json_path_query_lengthContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 102
                self.match(ASLIntrinsicParser.ATDOTLENGTHDASH)
                self.state = 103
                self.match(ASLIntrinsicParser.INT)
                pass
            else:
                raise NoViableAltException(self)

            self._ctx.stop = self._input.LT(-1)
            self.state = 115
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,9,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    localctx = ASLIntrinsicParser.Json_path_query_binaryContext(self, ASLIntrinsicParser.Json_path_queryContext(self, _parentctx, _parentState))
                    self.pushNewRecursionContext(localctx, _startState, self.RULE_json_path_query)
                    self.state = 106
                    if not self.precpred(self._ctx, 1):
                        from antlr4.error.Errors import FailedPredicateException
                        raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                    self.state = 109 
                    self._errHandler.sync(self)
                    _alt = 1
                    while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                        if _alt == 1:
                            self.state = 107
                            _la = self._input.LA(1)
                            if not(_la==13 or _la==14):
                                self._errHandler.recoverInline(self)
                            else:
                                self._errHandler.reportMatch(self)
                                self.consume()
                            self.state = 108
                            self.json_path_query(0)

                        else:
                            raise NoViableAltException(self)
                        self.state = 111 
                        self._errHandler.sync(self)
                        _alt = self._interp.adaptivePredict(self._input,8,self._ctx)
             
                self.state = 117
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,9,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class IdentifierContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def IDENTIFIER(self):
            return self.getToken(ASLIntrinsicParser.IDENTIFIER, 0)

        def state_fun_name(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.State_fun_nameContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_identifier

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIdentifier" ):
                listener.enterIdentifier(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIdentifier" ):
                listener.exitIdentifier(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIdentifier" ):
                return visitor.visitIdentifier(self)
            else:
                return visitor.visitChildren(self)




    def identifier(self):

        localctx = ASLIntrinsicParser.IdentifierContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_identifier)
        try:
            self.state = 120
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [41]:
                self.enterOuterAlt(localctx, 1)
                self.state = 118
                self.match(ASLIntrinsicParser.IDENTIFIER)
                pass
            elif token in [20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37]:
                self.enterOuterAlt(localctx, 2)
                self.state = 119
                self.state_fun_name()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx



    def sempred(self, localctx:RuleContext, ruleIndex:int, predIndex:int):
        if self._predicates == None:
            self._predicates = dict()
        self._predicates[11] = self.json_path_query_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def json_path_query_sempred(self, localctx:Json_path_queryContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 1)
         




