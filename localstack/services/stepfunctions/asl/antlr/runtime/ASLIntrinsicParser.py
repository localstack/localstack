# Generated from /Users/mep/LocalStack/localstack/localstack/services/stepfunctions/asl/antlr/ASLIntrinsicParser.g4 by ANTLR 4.11.1
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
        4,1,14,24,2,0,7,0,2,1,7,1,2,2,7,2,1,0,1,0,4,0,9,8,0,11,0,12,0,10,
        1,0,3,0,14,8,0,1,1,1,1,1,1,1,1,3,1,20,8,1,1,2,1,2,1,2,0,0,3,0,2,
        4,0,1,2,0,1,1,11,11,24,0,8,1,0,0,0,2,15,1,0,0,0,4,21,1,0,0,0,6,9,
        3,4,2,0,7,9,3,2,1,0,8,6,1,0,0,0,8,7,1,0,0,0,9,10,1,0,0,0,10,8,1,
        0,0,0,10,11,1,0,0,0,11,13,1,0,0,0,12,14,5,0,0,1,13,12,1,0,0,0,13,
        14,1,0,0,0,14,1,1,0,0,0,15,16,3,4,2,0,16,19,5,3,0,0,17,20,3,4,2,
        0,18,20,3,2,1,0,19,17,1,0,0,0,19,18,1,0,0,0,20,3,1,0,0,0,21,22,7,
        0,0,0,22,5,1,0,0,0,4,8,10,13,19
    ]

class ASLIntrinsicParser ( Parser ):

    grammarFileName = "ASLIntrinsicParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'$'", "'$$'", "'.'", "','", "'('", "')'", 
                     "'['", "']'", "'{'", "'}'" ]

    symbolicNames = [ "<INVALID>", "DOLLAR", "DDOLLAR", "DOT", "COMMA", 
                      "LPAREN", "RPAREN", "LBRACK", "RBRACK", "LBRACE", 
                      "RBRACE", "IDENTIFIER", "STRING", "NUMBER", "WS" ]

    RULE_compilation_unit = 0
    RULE_member_access = 1
    RULE_member = 2

    ruleNames =  [ "compilation_unit", "member_access", "member" ]

    EOF = Token.EOF
    DOLLAR=1
    DDOLLAR=2
    DOT=3
    COMMA=4
    LPAREN=5
    RPAREN=6
    LBRACK=7
    RBRACK=8
    LBRACE=9
    RBRACE=10
    IDENTIFIER=11
    STRING=12
    NUMBER=13
    WS=14

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.11.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class Compilation_unitContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def member(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.MemberContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.MemberContext,i)


        def member_access(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.Member_accessContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.Member_accessContext,i)


        def EOF(self):
            return self.getToken(ASLIntrinsicParser.EOF, 0)

        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_compilation_unit

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCompilation_unit" ):
                listener.enterCompilation_unit(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCompilation_unit" ):
                listener.exitCompilation_unit(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCompilation_unit" ):
                return visitor.visitCompilation_unit(self)
            else:
                return visitor.visitChildren(self)




    def compilation_unit(self):

        localctx = ASLIntrinsicParser.Compilation_unitContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_compilation_unit)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 8 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 8
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,0,self._ctx)
                if la_ == 1:
                    self.state = 6
                    self.member()
                    pass

                elif la_ == 2:
                    self.state = 7
                    self.member_access()
                    pass


                self.state = 10 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not (_la==1 or _la==11):
                    break

            self.state = 13
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
            if la_ == 1:
                self.state = 12
                self.match(ASLIntrinsicParser.EOF)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Member_accessContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def member(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ASLIntrinsicParser.MemberContext)
            else:
                return self.getTypedRuleContext(ASLIntrinsicParser.MemberContext,i)


        def DOT(self):
            return self.getToken(ASLIntrinsicParser.DOT, 0)

        def member_access(self):
            return self.getTypedRuleContext(ASLIntrinsicParser.Member_accessContext,0)


        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_member_access

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMember_access" ):
                listener.enterMember_access(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMember_access" ):
                listener.exitMember_access(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMember_access" ):
                return visitor.visitMember_access(self)
            else:
                return visitor.visitChildren(self)




    def member_access(self):

        localctx = ASLIntrinsicParser.Member_accessContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_member_access)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 15
            self.member()
            self.state = 16
            self.match(ASLIntrinsicParser.DOT)
            self.state = 19
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,3,self._ctx)
            if la_ == 1:
                self.state = 17
                self.member()
                pass

            elif la_ == 2:
                self.state = 18
                self.member_access()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MemberContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOLLAR(self):
            return self.getToken(ASLIntrinsicParser.DOLLAR, 0)

        def IDENTIFIER(self):
            return self.getToken(ASLIntrinsicParser.IDENTIFIER, 0)

        def getRuleIndex(self):
            return ASLIntrinsicParser.RULE_member

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMember" ):
                listener.enterMember(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMember" ):
                listener.exitMember(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMember" ):
                return visitor.visitMember(self)
            else:
                return visitor.visitChildren(self)




    def member(self):

        localctx = ASLIntrinsicParser.MemberContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_member)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 21
            _la = self._input.LA(1)
            if not(_la==1 or _la==11):
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





