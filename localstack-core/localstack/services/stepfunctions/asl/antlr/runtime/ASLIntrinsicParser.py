# Generated from ASLIntrinsicParser.g4 by ANTLR 4.13.2
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
        4,1,33,45,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,1,0,1,0,1,0,1,
        1,1,1,1,1,1,1,1,1,1,2,1,2,1,3,1,3,1,3,1,3,5,3,25,8,3,10,3,12,3,28,
        9,3,1,3,1,3,1,3,1,3,3,3,34,8,3,1,4,1,4,1,4,1,4,1,4,1,4,1,4,3,4,43,
        8,4,1,4,0,0,5,0,2,4,6,8,0,2,1,0,11,28,1,0,8,9,47,0,10,1,0,0,0,2,
        13,1,0,0,0,4,18,1,0,0,0,6,33,1,0,0,0,8,42,1,0,0,0,10,11,3,2,1,0,
        11,12,5,0,0,1,12,1,1,0,0,0,13,14,5,10,0,0,14,15,5,7,0,0,15,16,3,
        4,2,0,16,17,3,6,3,0,17,3,1,0,0,0,18,19,7,0,0,0,19,5,1,0,0,0,20,21,
        5,4,0,0,21,26,3,8,4,0,22,23,5,6,0,0,23,25,3,8,4,0,24,22,1,0,0,0,
        25,28,1,0,0,0,26,24,1,0,0,0,26,27,1,0,0,0,27,29,1,0,0,0,28,26,1,
        0,0,0,29,30,5,5,0,0,30,34,1,0,0,0,31,32,5,4,0,0,32,34,5,5,0,0,33,
        20,1,0,0,0,33,31,1,0,0,0,34,7,1,0,0,0,35,43,5,29,0,0,36,43,5,30,
        0,0,37,43,5,31,0,0,38,43,7,1,0,0,39,43,5,1,0,0,40,43,5,2,0,0,41,
        43,3,2,1,0,42,35,1,0,0,0,42,36,1,0,0,0,42,37,1,0,0,0,42,38,1,0,0,
        0,42,39,1,0,0,0,42,40,1,0,0,0,42,41,1,0,0,0,43,9,1,0,0,0,3,26,33,
        42
    ]

class ASLIntrinsicParser ( Parser ):

    grammarFileName = "ASLIntrinsicParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "'$'", "'('", 
                     "')'", "','", "'.'", "'true'", "'false'", "'States'", 
                     "'Format'", "'StringToJson'", "'JsonToString'", "'Array'", 
                     "'ArrayPartition'", "'ArrayContains'", "'ArrayRange'", 
                     "'ArrayGetItem'", "'ArrayLength'", "'ArrayUnique'", 
                     "'Base64Encode'", "'Base64Decode'", "'Hash'", "'JsonMerge'", 
                     "'MathRandom'", "'MathAdd'", "'StringSplit'", "'UUID'" ]

    symbolicNames = [ "<INVALID>", "CONTEXT_PATH_STRING", "JSON_PATH_STRING", 
                      "DOLLAR", "LPAREN", "RPAREN", "COMMA", "DOT", "TRUE", 
                      "FALSE", "States", "Format", "StringToJson", "JsonToString", 
                      "Array", "ArrayPartition", "ArrayContains", "ArrayRange", 
                      "ArrayGetItem", "ArrayLength", "ArrayUnique", "Base64Encode", 
                      "Base64Decode", "Hash", "JsonMerge", "MathRandom", 
                      "MathAdd", "StringSplit", "UUID", "STRING", "INT", 
                      "NUMBER", "IDENTIFIER", "WS" ]

    RULE_func_decl = 0
    RULE_states_func_decl = 1
    RULE_state_fun_name = 2
    RULE_func_arg_list = 3
    RULE_func_arg = 4

    ruleNames =  [ "func_decl", "states_func_decl", "state_fun_name", "func_arg_list", 
                   "func_arg" ]

    EOF = Token.EOF
    CONTEXT_PATH_STRING=1
    JSON_PATH_STRING=2
    DOLLAR=3
    LPAREN=4
    RPAREN=5
    COMMA=6
    DOT=7
    TRUE=8
    FALSE=9
    States=10
    Format=11
    StringToJson=12
    JsonToString=13
    Array=14
    ArrayPartition=15
    ArrayContains=16
    ArrayRange=17
    ArrayGetItem=18
    ArrayLength=19
    ArrayUnique=20
    Base64Encode=21
    Base64Decode=22
    Hash=23
    JsonMerge=24
    MathRandom=25
    MathAdd=26
    StringSplit=27
    UUID=28
    STRING=29
    INT=30
    NUMBER=31
    IDENTIFIER=32
    WS=33

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.2")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class Func_declContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def states_func_decl(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.States_func_declContext,0)


        def EOF(self):
            return self.getToken(ASLIntrinsicParser.EOF, 0)

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
            self.state = 10
            self.states_func_decl()
            self.state = 11
            self.match(ASLIntrinsicParser.EOF)
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
            self.state = 13
            self.match(ASLIntrinsicParser.States)
            self.state = 14
            self.match(ASLIntrinsicParser.DOT)
            self.state = 15
            self.state_fun_name()
            self.state = 16
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
            self.state = 18
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 536868864) != 0)):
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
            self.state = 33
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 20
                self.match(ASLIntrinsicParser.LPAREN)
                self.state = 21
                self.func_arg()
                self.state = 26
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==6:
                    self.state = 22
                    self.match(ASLIntrinsicParser.COMMA)
                    self.state = 23
                    self.func_arg()
                    self.state = 28
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 29
                self.match(ASLIntrinsicParser.RPAREN)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 31
                self.match(ASLIntrinsicParser.LPAREN)
                self.state = 32
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

        def CONTEXT_PATH_STRING(self):
            return self.getToken(ASLIntrinsicParser.CONTEXT_PATH_STRING, 0)

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

        def states_func_decl(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.States_func_declContext,0)


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

        def JSON_PATH_STRING(self):
            return self.getToken(ASLIntrinsicParser.JSON_PATH_STRING, 0)

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
            self.state = 42
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [29]:
                localctx = ASLIntrinsicParser.Func_arg_stringContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 35
                self.match(ASLIntrinsicParser.STRING)
                pass
            elif token in [30]:
                localctx = ASLIntrinsicParser.Func_arg_intContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 36
                self.match(ASLIntrinsicParser.INT)
                pass
            elif token in [31]:
                localctx = ASLIntrinsicParser.Func_arg_floatContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 37
                self.match(ASLIntrinsicParser.NUMBER)
                pass
            elif token in [8, 9]:
                localctx = ASLIntrinsicParser.Func_arg_boolContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 38
                _la = self._input.LA(1)
                if not(_la==8 or _la==9):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                pass
            elif token in [1]:
                localctx = ASLIntrinsicParser.Func_arg_context_pathContext(self, localctx)
                self.enterOuterAlt(localctx, 5)
                self.state = 39
                self.match(ASLIntrinsicParser.CONTEXT_PATH_STRING)
                pass
            elif token in [2]:
                localctx = ASLIntrinsicParser.Func_arg_json_pathContext(self, localctx)
                self.enterOuterAlt(localctx, 6)
                self.state = 40
                self.match(ASLIntrinsicParser.JSON_PATH_STRING)
                pass
            elif token in [10]:
                localctx = ASLIntrinsicParser.Func_arg_func_declContext(self, localctx)
                self.enterOuterAlt(localctx, 7)
                self.state = 41
                self.states_func_decl()
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





