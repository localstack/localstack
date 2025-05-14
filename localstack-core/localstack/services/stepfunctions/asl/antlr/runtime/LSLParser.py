# Generated from LSLParser.g4 by ANTLR 4.13.2
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
        4,1,48,207,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,1,0,1,0,1,0,4,0,50,8,0,11,0,12,0,51,1,0,
        1,0,1,1,1,1,1,1,1,1,1,1,1,2,1,2,1,2,1,2,1,2,1,2,3,2,67,8,2,1,3,1,
        3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,3,3,78,8,3,1,4,1,4,1,5,1,5,3,5,84,
        8,5,1,5,3,5,87,8,5,1,6,1,6,1,6,3,6,92,8,6,1,7,1,7,1,7,1,8,1,8,1,
        8,1,8,5,8,101,8,8,10,8,12,8,104,9,8,1,8,1,8,1,9,1,9,1,9,1,9,1,10,
        1,10,3,10,114,8,10,1,10,1,10,5,10,118,8,10,10,10,12,10,121,9,10,
        1,10,1,10,1,11,1,11,1,11,1,11,5,11,129,8,11,10,11,12,11,132,9,11,
        1,11,1,11,1,12,1,12,1,12,1,12,1,13,1,13,1,13,1,14,1,14,1,14,1,15,
        1,15,1,15,1,15,1,15,1,15,3,15,152,8,15,1,16,1,16,1,16,3,16,157,8,
        16,1,17,1,17,1,17,1,17,5,17,163,8,17,10,17,12,17,166,9,17,1,17,1,
        17,1,17,1,17,3,17,172,8,17,1,18,1,18,1,18,1,18,1,19,1,19,1,19,1,
        19,5,19,182,8,19,10,19,12,19,185,9,19,1,19,1,19,1,19,1,19,3,19,191,
        8,19,1,20,1,20,1,20,1,20,1,20,1,20,3,20,199,8,20,1,21,1,21,3,21,
        203,8,21,1,22,1,22,1,22,0,0,23,0,2,4,6,8,10,12,14,16,18,20,22,24,
        26,28,30,32,34,36,38,40,42,44,0,3,2,0,43,43,46,46,1,0,28,29,2,0,
        3,17,43,43,210,0,49,1,0,0,0,2,55,1,0,0,0,4,66,1,0,0,0,6,77,1,0,0,
        0,8,79,1,0,0,0,10,81,1,0,0,0,12,88,1,0,0,0,14,93,1,0,0,0,16,96,1,
        0,0,0,18,107,1,0,0,0,20,111,1,0,0,0,22,124,1,0,0,0,24,135,1,0,0,
        0,26,139,1,0,0,0,28,142,1,0,0,0,30,151,1,0,0,0,32,156,1,0,0,0,34,
        171,1,0,0,0,36,173,1,0,0,0,38,190,1,0,0,0,40,198,1,0,0,0,42,202,
        1,0,0,0,44,204,1,0,0,0,46,50,3,2,1,0,47,50,3,30,15,0,48,50,3,4,2,
        0,49,46,1,0,0,0,49,47,1,0,0,0,49,48,1,0,0,0,50,51,1,0,0,0,51,49,
        1,0,0,0,51,52,1,0,0,0,52,53,1,0,0,0,53,54,5,0,0,1,54,1,1,0,0,0,55,
        56,5,46,0,0,56,57,3,20,10,0,57,58,5,19,0,0,58,59,3,6,3,0,59,3,1,
        0,0,0,60,61,5,46,0,0,61,67,3,22,11,0,62,63,5,46,0,0,63,64,5,32,0,
        0,64,67,3,6,3,0,65,67,3,6,3,0,66,60,1,0,0,0,66,62,1,0,0,0,66,65,
        1,0,0,0,67,5,1,0,0,0,68,69,3,8,4,0,69,70,5,21,0,0,70,71,5,46,0,0,
        71,72,3,10,5,0,72,78,1,0,0,0,73,74,5,33,0,0,74,78,3,12,6,0,75,76,
        5,35,0,0,76,78,3,32,16,0,77,68,1,0,0,0,77,73,1,0,0,0,77,75,1,0,0,
        0,78,7,1,0,0,0,79,80,5,38,0,0,80,9,1,0,0,0,81,83,5,31,0,0,82,84,
        3,14,7,0,83,82,1,0,0,0,83,84,1,0,0,0,84,86,1,0,0,0,85,87,3,16,8,
        0,86,85,1,0,0,0,86,87,1,0,0,0,87,11,1,0,0,0,88,89,5,31,0,0,89,91,
        3,26,13,0,90,92,3,28,14,0,91,90,1,0,0,0,91,92,1,0,0,0,92,13,1,0,
        0,0,93,94,5,39,0,0,94,95,3,32,16,0,95,15,1,0,0,0,96,97,5,40,0,0,
        97,98,5,26,0,0,98,102,3,18,9,0,99,101,3,18,9,0,100,99,1,0,0,0,101,
        104,1,0,0,0,102,100,1,0,0,0,102,103,1,0,0,0,103,105,1,0,0,0,104,
        102,1,0,0,0,105,106,5,27,0,0,106,17,1,0,0,0,107,108,3,44,22,0,108,
        109,5,18,0,0,109,110,3,4,2,0,110,19,1,0,0,0,111,113,5,22,0,0,112,
        114,5,46,0,0,113,112,1,0,0,0,113,114,1,0,0,0,114,119,1,0,0,0,115,
        116,5,20,0,0,116,118,5,46,0,0,117,115,1,0,0,0,118,121,1,0,0,0,119,
        117,1,0,0,0,119,120,1,0,0,0,120,122,1,0,0,0,121,119,1,0,0,0,122,
        123,5,23,0,0,123,21,1,0,0,0,124,125,5,22,0,0,125,130,3,24,12,0,126,
        127,5,20,0,0,127,129,3,24,12,0,128,126,1,0,0,0,129,132,1,0,0,0,130,
        128,1,0,0,0,130,131,1,0,0,0,131,133,1,0,0,0,132,130,1,0,0,0,133,
        134,5,23,0,0,134,23,1,0,0,0,135,136,5,46,0,0,136,137,5,19,0,0,137,
        138,3,32,16,0,138,25,1,0,0,0,139,140,5,36,0,0,140,141,3,42,21,0,
        141,27,1,0,0,0,142,143,5,37,0,0,143,144,3,42,21,0,144,29,1,0,0,0,
        145,146,5,46,0,0,146,147,5,19,0,0,147,152,3,4,2,0,148,149,5,46,0,
        0,149,150,5,19,0,0,150,152,3,32,16,0,151,145,1,0,0,0,151,148,1,0,
        0,0,152,31,1,0,0,0,153,157,3,34,17,0,154,157,3,38,19,0,155,157,3,
        40,20,0,156,153,1,0,0,0,156,154,1,0,0,0,156,155,1,0,0,0,157,33,1,
        0,0,0,158,159,5,26,0,0,159,164,3,36,18,0,160,161,5,20,0,0,161,163,
        3,36,18,0,162,160,1,0,0,0,163,166,1,0,0,0,164,162,1,0,0,0,164,165,
        1,0,0,0,165,167,1,0,0,0,166,164,1,0,0,0,167,168,5,27,0,0,168,172,
        1,0,0,0,169,170,5,26,0,0,170,172,5,27,0,0,171,158,1,0,0,0,171,169,
        1,0,0,0,172,35,1,0,0,0,173,174,7,0,0,0,174,175,5,21,0,0,175,176,
        3,32,16,0,176,37,1,0,0,0,177,178,5,24,0,0,178,183,3,32,16,0,179,
        180,5,20,0,0,180,182,3,32,16,0,181,179,1,0,0,0,182,185,1,0,0,0,183,
        181,1,0,0,0,183,184,1,0,0,0,184,186,1,0,0,0,185,183,1,0,0,0,186,
        187,5,25,0,0,187,191,1,0,0,0,188,189,5,24,0,0,189,191,5,25,0,0,190,
        177,1,0,0,0,190,188,1,0,0,0,191,39,1,0,0,0,192,199,5,45,0,0,193,
        199,5,44,0,0,194,199,7,1,0,0,195,199,5,30,0,0,196,199,5,43,0,0,197,
        199,5,2,0,0,198,192,1,0,0,0,198,193,1,0,0,0,198,194,1,0,0,0,198,
        195,1,0,0,0,198,196,1,0,0,0,198,197,1,0,0,0,199,41,1,0,0,0,200,203,
        5,43,0,0,201,203,5,2,0,0,202,200,1,0,0,0,202,201,1,0,0,0,203,43,
        1,0,0,0,204,205,7,2,0,0,205,45,1,0,0,0,19,49,51,66,77,83,86,91,102,
        113,119,130,151,156,164,171,183,190,198,202
    ]

class LSLParser ( Parser ):

    grammarFileName = "LSLParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "'States.ALL'", 
                     "'States.DataLimitExceeded'", "'States.HeartbeatTimeout'", 
                     "'States.Timeout'", "'States.TaskFailed'", "'States.Permissions'", 
                     "'States.ResultPathMatchFailure'", "'States.ParameterPathFailure'", 
                     "'States.BranchFailed'", "'States.NoChoiceMatched'", 
                     "'States.IntrinsicFailure'", "'States.ExceedToleratedFailureThreshold'", 
                     "'States.ItemReaderFailed'", "'States.ResultWriterFailed'", 
                     "'States.QueryEvaluationError'", "'->'", "'='", "','", 
                     "':'", "'('", "')'", "'['", "']'", "'{'", "'}'", "'true'", 
                     "'false'", "'null'", "'where'", "'as'", "'fail'", "'output'", 
                     "'return'", "'error'", "'cause'", "'lambda'", "'arguments'", 
                     "'catch'" ]

    symbolicNames = [ "<INVALID>", "LINECOMMENT", "JSONATA", "ERRORNAMEStatesALL", 
                      "ERRORNAMEStatesDataLimitExceeded", "ERRORNAMEStatesHeartbeatTimeout", 
                      "ERRORNAMEStatesTimeout", "ERRORNAMEStatesTaskFailed", 
                      "ERRORNAMEStatesPermissions", "ERRORNAMEStatesResultPathMatchFailure", 
                      "ERRORNAMEStatesParameterPathFailure", "ERRORNAMEStatesBranchFailed", 
                      "ERRORNAMEStatesNoChoiceMatched", "ERRORNAMEStatesIntrinsicFailure", 
                      "ERRORNAMEStatesExceedToleratedFailureThreshold", 
                      "ERRORNAMEStatesItemReaderFailed", "ERRORNAMEStatesResultWriterFailed", 
                      "ERRORNAMEStatesQueryEvaluationError", "ARROW", "EQUALS", 
                      "COMMA", "COLON", "LPAREN", "RPAREN", "LBRACK", "RBRACK", 
                      "LBRACE", "RBRACE", "TRUE", "FALSE", "NULL", "WHERE", 
                      "AS", "FAIL", "OUTPUT", "RETURN", "ERROR", "CAUSE", 
                      "LAMBDA", "ARGUMENTS", "CATCH", "STRINGPATH", "VAR", 
                      "STRING", "INT", "NUMBER", "IDEN", "WS", "TOK" ]

    RULE_state_machine = 0
    RULE_state_declaration = 1
    RULE_state_call = 2
    RULE_state = 3
    RULE_service_name = 4
    RULE_task_where = 5
    RULE_fail_where = 6
    RULE_arguments = 7
    RULE_catch_block = 8
    RULE_catch_case = 9
    RULE_parameter_list = 10
    RULE_args_assign_list = 11
    RULE_args_assign = 12
    RULE_error = 13
    RULE_cause = 14
    RULE_var_assign = 15
    RULE_json_value = 16
    RULE_json_object = 17
    RULE_json_binding = 18
    RULE_json_arr = 19
    RULE_json_value_lit = 20
    RULE_string_or_jsonata = 21
    RULE_error_name = 22

    ruleNames =  [ "state_machine", "state_declaration", "state_call", "state", 
                   "service_name", "task_where", "fail_where", "arguments", 
                   "catch_block", "catch_case", "parameter_list", "args_assign_list", 
                   "args_assign", "error", "cause", "var_assign", "json_value", 
                   "json_object", "json_binding", "json_arr", "json_value_lit", 
                   "string_or_jsonata", "error_name" ]

    EOF = Token.EOF
    LINECOMMENT=1
    JSONATA=2
    ERRORNAMEStatesALL=3
    ERRORNAMEStatesDataLimitExceeded=4
    ERRORNAMEStatesHeartbeatTimeout=5
    ERRORNAMEStatesTimeout=6
    ERRORNAMEStatesTaskFailed=7
    ERRORNAMEStatesPermissions=8
    ERRORNAMEStatesResultPathMatchFailure=9
    ERRORNAMEStatesParameterPathFailure=10
    ERRORNAMEStatesBranchFailed=11
    ERRORNAMEStatesNoChoiceMatched=12
    ERRORNAMEStatesIntrinsicFailure=13
    ERRORNAMEStatesExceedToleratedFailureThreshold=14
    ERRORNAMEStatesItemReaderFailed=15
    ERRORNAMEStatesResultWriterFailed=16
    ERRORNAMEStatesQueryEvaluationError=17
    ARROW=18
    EQUALS=19
    COMMA=20
    COLON=21
    LPAREN=22
    RPAREN=23
    LBRACK=24
    RBRACK=25
    LBRACE=26
    RBRACE=27
    TRUE=28
    FALSE=29
    NULL=30
    WHERE=31
    AS=32
    FAIL=33
    OUTPUT=34
    RETURN=35
    ERROR=36
    CAUSE=37
    LAMBDA=38
    ARGUMENTS=39
    CATCH=40
    STRINGPATH=41
    VAR=42
    STRING=43
    INT=44
    NUMBER=45
    IDEN=46
    WS=47
    TOK=48

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.2")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class State_machineContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EOF(self):
            return self.getToken(LSLParser.EOF, 0)

        def state_declaration(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.State_declarationContext)
            else:
                return self.getTypedRuleContext(LSLParser.State_declarationContext,i)


        def var_assign(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.Var_assignContext)
            else:
                return self.getTypedRuleContext(LSLParser.Var_assignContext,i)


        def state_call(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.State_callContext)
            else:
                return self.getTypedRuleContext(LSLParser.State_callContext,i)


        def getRuleIndex(self):
            return LSLParser.RULE_state_machine

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_machine" ):
                listener.enterState_machine(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_machine" ):
                listener.exitState_machine(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_machine" ):
                return visitor.visitState_machine(self)
            else:
                return visitor.visitChildren(self)




    def state_machine(self):

        localctx = LSLParser.State_machineContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_state_machine)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 49 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 49
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,0,self._ctx)
                if la_ == 1:
                    self.state = 46
                    self.state_declaration()
                    pass

                elif la_ == 2:
                    self.state = 47
                    self.var_assign()
                    pass

                elif la_ == 3:
                    self.state = 48
                    self.state_call()
                    pass


                self.state = 51 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 70686571757568) != 0)):
                    break

            self.state = 53
            self.match(LSLParser.EOF)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class State_declarationContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)

        def parameter_list(self):
            return self.getTypedRuleContext(LSLParser.Parameter_listContext,0)


        def EQUALS(self):
            return self.getToken(LSLParser.EQUALS, 0)

        def state_(self):
            return self.getTypedRuleContext(LSLParser.StateContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_state_declaration

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_declaration" ):
                listener.enterState_declaration(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_declaration" ):
                listener.exitState_declaration(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_declaration" ):
                return visitor.visitState_declaration(self)
            else:
                return visitor.visitChildren(self)




    def state_declaration(self):

        localctx = LSLParser.State_declarationContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_state_declaration)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 55
            self.match(LSLParser.IDEN)
            self.state = 56
            self.parameter_list()
            self.state = 57
            self.match(LSLParser.EQUALS)
            self.state = 58
            self.state_()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class State_callContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return LSLParser.RULE_state_call

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class State_call_templateContext(State_callContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.State_callContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)
        def args_assign_list(self):
            return self.getTypedRuleContext(LSLParser.Args_assign_listContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_call_template" ):
                listener.enterState_call_template(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_call_template" ):
                listener.exitState_call_template(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_call_template" ):
                return visitor.visitState_call_template(self)
            else:
                return visitor.visitChildren(self)


    class State_call_anonymousContext(State_callContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.State_callContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def state_(self):
            return self.getTypedRuleContext(LSLParser.StateContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_call_anonymous" ):
                listener.enterState_call_anonymous(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_call_anonymous" ):
                listener.exitState_call_anonymous(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_call_anonymous" ):
                return visitor.visitState_call_anonymous(self)
            else:
                return visitor.visitChildren(self)


    class State_call_namedContext(State_callContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.State_callContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)
        def AS(self):
            return self.getToken(LSLParser.AS, 0)
        def state_(self):
            return self.getTypedRuleContext(LSLParser.StateContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_call_named" ):
                listener.enterState_call_named(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_call_named" ):
                listener.exitState_call_named(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_call_named" ):
                return visitor.visitState_call_named(self)
            else:
                return visitor.visitChildren(self)



    def state_call(self):

        localctx = LSLParser.State_callContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_state_call)
        try:
            self.state = 66
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
            if la_ == 1:
                localctx = LSLParser.State_call_templateContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 60
                self.match(LSLParser.IDEN)
                self.state = 61
                self.args_assign_list()
                pass

            elif la_ == 2:
                localctx = LSLParser.State_call_namedContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 62
                self.match(LSLParser.IDEN)
                self.state = 63
                self.match(LSLParser.AS)
                self.state = 64
                self.state_()
                pass

            elif la_ == 3:
                localctx = LSLParser.State_call_anonymousContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 65
                self.state_()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class StateContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return LSLParser.RULE_state

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class State_failContext(StateContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.StateContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def FAIL(self):
            return self.getToken(LSLParser.FAIL, 0)
        def fail_where(self):
            return self.getTypedRuleContext(LSLParser.Fail_whereContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_fail" ):
                listener.enterState_fail(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_fail" ):
                listener.exitState_fail(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_fail" ):
                return visitor.visitState_fail(self)
            else:
                return visitor.visitChildren(self)


    class State_returnContext(StateContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.StateContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def RETURN(self):
            return self.getToken(LSLParser.RETURN, 0)
        def json_value(self):
            return self.getTypedRuleContext(LSLParser.Json_valueContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_return" ):
                listener.enterState_return(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_return" ):
                listener.exitState_return(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_return" ):
                return visitor.visitState_return(self)
            else:
                return visitor.visitChildren(self)


    class State_taskContext(StateContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.StateContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def service_name(self):
            return self.getTypedRuleContext(LSLParser.Service_nameContext,0)

        def COLON(self):
            return self.getToken(LSLParser.COLON, 0)
        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)
        def task_where(self):
            return self.getTypedRuleContext(LSLParser.Task_whereContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterState_task" ):
                listener.enterState_task(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitState_task" ):
                listener.exitState_task(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitState_task" ):
                return visitor.visitState_task(self)
            else:
                return visitor.visitChildren(self)



    def state_(self):

        localctx = LSLParser.StateContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_state)
        try:
            self.state = 77
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [38]:
                localctx = LSLParser.State_taskContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 68
                self.service_name()
                self.state = 69
                self.match(LSLParser.COLON)
                self.state = 70
                self.match(LSLParser.IDEN)
                self.state = 71
                self.task_where()
                pass
            elif token in [33]:
                localctx = LSLParser.State_failContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 73
                self.match(LSLParser.FAIL)
                self.state = 74
                self.fail_where()
                pass
            elif token in [35]:
                localctx = LSLParser.State_returnContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 75
                self.match(LSLParser.RETURN)
                self.state = 76
                self.json_value()
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


    class Service_nameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LAMBDA(self):
            return self.getToken(LSLParser.LAMBDA, 0)

        def getRuleIndex(self):
            return LSLParser.RULE_service_name

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterService_name" ):
                listener.enterService_name(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitService_name" ):
                listener.exitService_name(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitService_name" ):
                return visitor.visitService_name(self)
            else:
                return visitor.visitChildren(self)




    def service_name(self):

        localctx = LSLParser.Service_nameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_service_name)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 79
            self.match(LSLParser.LAMBDA)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Task_whereContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WHERE(self):
            return self.getToken(LSLParser.WHERE, 0)

        def arguments(self):
            return self.getTypedRuleContext(LSLParser.ArgumentsContext,0)


        def catch_block(self):
            return self.getTypedRuleContext(LSLParser.Catch_blockContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_task_where

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterTask_where" ):
                listener.enterTask_where(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitTask_where" ):
                listener.exitTask_where(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitTask_where" ):
                return visitor.visitTask_where(self)
            else:
                return visitor.visitChildren(self)




    def task_where(self):

        localctx = LSLParser.Task_whereContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_task_where)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 81
            self.match(LSLParser.WHERE)
            self.state = 83
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==39:
                self.state = 82
                self.arguments()


            self.state = 86
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==40:
                self.state = 85
                self.catch_block()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Fail_whereContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WHERE(self):
            return self.getToken(LSLParser.WHERE, 0)

        def error(self):
            return self.getTypedRuleContext(LSLParser.ErrorContext,0)


        def cause(self):
            return self.getTypedRuleContext(LSLParser.CauseContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_fail_where

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFail_where" ):
                listener.enterFail_where(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFail_where" ):
                listener.exitFail_where(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFail_where" ):
                return visitor.visitFail_where(self)
            else:
                return visitor.visitChildren(self)




    def fail_where(self):

        localctx = LSLParser.Fail_whereContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_fail_where)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 88
            self.match(LSLParser.WHERE)
            self.state = 89
            self.error()
            self.state = 91
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==37:
                self.state = 90
                self.cause()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ArgumentsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ARGUMENTS(self):
            return self.getToken(LSLParser.ARGUMENTS, 0)

        def json_value(self):
            return self.getTypedRuleContext(LSLParser.Json_valueContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_arguments

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterArguments" ):
                listener.enterArguments(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitArguments" ):
                listener.exitArguments(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitArguments" ):
                return visitor.visitArguments(self)
            else:
                return visitor.visitChildren(self)




    def arguments(self):

        localctx = LSLParser.ArgumentsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_arguments)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 93
            self.match(LSLParser.ARGUMENTS)
            self.state = 94
            self.json_value()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Catch_blockContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def CATCH(self):
            return self.getToken(LSLParser.CATCH, 0)

        def LBRACE(self):
            return self.getToken(LSLParser.LBRACE, 0)

        def catch_case(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.Catch_caseContext)
            else:
                return self.getTypedRuleContext(LSLParser.Catch_caseContext,i)


        def RBRACE(self):
            return self.getToken(LSLParser.RBRACE, 0)

        def getRuleIndex(self):
            return LSLParser.RULE_catch_block

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCatch_block" ):
                listener.enterCatch_block(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCatch_block" ):
                listener.exitCatch_block(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCatch_block" ):
                return visitor.visitCatch_block(self)
            else:
                return visitor.visitChildren(self)




    def catch_block(self):

        localctx = LSLParser.Catch_blockContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_catch_block)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 96
            self.match(LSLParser.CATCH)
            self.state = 97
            self.match(LSLParser.LBRACE)
            self.state = 98
            self.catch_case()
            self.state = 102
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & 8796093284344) != 0):
                self.state = 99
                self.catch_case()
                self.state = 104
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 105
            self.match(LSLParser.RBRACE)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Catch_caseContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def error_name(self):
            return self.getTypedRuleContext(LSLParser.Error_nameContext,0)


        def ARROW(self):
            return self.getToken(LSLParser.ARROW, 0)

        def state_call(self):
            return self.getTypedRuleContext(LSLParser.State_callContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_catch_case

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCatch_case" ):
                listener.enterCatch_case(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCatch_case" ):
                listener.exitCatch_case(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCatch_case" ):
                return visitor.visitCatch_case(self)
            else:
                return visitor.visitChildren(self)




    def catch_case(self):

        localctx = LSLParser.Catch_caseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_catch_case)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 107
            self.error_name()
            self.state = 108
            self.match(LSLParser.ARROW)
            self.state = 109
            self.state_call()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Parameter_listContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LPAREN(self):
            return self.getToken(LSLParser.LPAREN, 0)

        def RPAREN(self):
            return self.getToken(LSLParser.RPAREN, 0)

        def IDEN(self, i:int=None):
            if i is None:
                return self.getTokens(LSLParser.IDEN)
            else:
                return self.getToken(LSLParser.IDEN, i)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(LSLParser.COMMA)
            else:
                return self.getToken(LSLParser.COMMA, i)

        def getRuleIndex(self):
            return LSLParser.RULE_parameter_list

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterParameter_list" ):
                listener.enterParameter_list(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitParameter_list" ):
                listener.exitParameter_list(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitParameter_list" ):
                return visitor.visitParameter_list(self)
            else:
                return visitor.visitChildren(self)




    def parameter_list(self):

        localctx = LSLParser.Parameter_listContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_parameter_list)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 111
            self.match(LSLParser.LPAREN)
            self.state = 113
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==46:
                self.state = 112
                self.match(LSLParser.IDEN)


            self.state = 119
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==20:
                self.state = 115
                self.match(LSLParser.COMMA)
                self.state = 116
                self.match(LSLParser.IDEN)
                self.state = 121
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 122
            self.match(LSLParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Args_assign_listContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LPAREN(self):
            return self.getToken(LSLParser.LPAREN, 0)

        def args_assign(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.Args_assignContext)
            else:
                return self.getTypedRuleContext(LSLParser.Args_assignContext,i)


        def RPAREN(self):
            return self.getToken(LSLParser.RPAREN, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(LSLParser.COMMA)
            else:
                return self.getToken(LSLParser.COMMA, i)

        def getRuleIndex(self):
            return LSLParser.RULE_args_assign_list

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterArgs_assign_list" ):
                listener.enterArgs_assign_list(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitArgs_assign_list" ):
                listener.exitArgs_assign_list(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitArgs_assign_list" ):
                return visitor.visitArgs_assign_list(self)
            else:
                return visitor.visitChildren(self)




    def args_assign_list(self):

        localctx = LSLParser.Args_assign_listContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_args_assign_list)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 124
            self.match(LSLParser.LPAREN)
            self.state = 125
            self.args_assign()
            self.state = 130
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==20:
                self.state = 126
                self.match(LSLParser.COMMA)
                self.state = 127
                self.args_assign()
                self.state = 132
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 133
            self.match(LSLParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Args_assignContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)

        def EQUALS(self):
            return self.getToken(LSLParser.EQUALS, 0)

        def json_value(self):
            return self.getTypedRuleContext(LSLParser.Json_valueContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_args_assign

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterArgs_assign" ):
                listener.enterArgs_assign(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitArgs_assign" ):
                listener.exitArgs_assign(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitArgs_assign" ):
                return visitor.visitArgs_assign(self)
            else:
                return visitor.visitChildren(self)




    def args_assign(self):

        localctx = LSLParser.Args_assignContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_args_assign)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 135
            self.match(LSLParser.IDEN)
            self.state = 136
            self.match(LSLParser.EQUALS)
            self.state = 137
            self.json_value()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ErrorContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ERROR(self):
            return self.getToken(LSLParser.ERROR, 0)

        def string_or_jsonata(self):
            return self.getTypedRuleContext(LSLParser.String_or_jsonataContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_error

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterError" ):
                listener.enterError(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitError" ):
                listener.exitError(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitError" ):
                return visitor.visitError(self)
            else:
                return visitor.visitChildren(self)




    def error(self):

        localctx = LSLParser.ErrorContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_error)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 139
            self.match(LSLParser.ERROR)
            self.state = 140
            self.string_or_jsonata()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CauseContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def CAUSE(self):
            return self.getToken(LSLParser.CAUSE, 0)

        def string_or_jsonata(self):
            return self.getTypedRuleContext(LSLParser.String_or_jsonataContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_cause

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCause" ):
                listener.enterCause(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCause" ):
                listener.exitCause(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCause" ):
                return visitor.visitCause(self)
            else:
                return visitor.visitChildren(self)




    def cause(self):

        localctx = LSLParser.CauseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 28, self.RULE_cause)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 142
            self.match(LSLParser.CAUSE)
            self.state = 143
            self.string_or_jsonata()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Var_assignContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return LSLParser.RULE_var_assign

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class Var_assign_state_callContext(Var_assignContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Var_assignContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)
        def EQUALS(self):
            return self.getToken(LSLParser.EQUALS, 0)
        def state_call(self):
            return self.getTypedRuleContext(LSLParser.State_callContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterVar_assign_state_call" ):
                listener.enterVar_assign_state_call(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitVar_assign_state_call" ):
                listener.exitVar_assign_state_call(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitVar_assign_state_call" ):
                return visitor.visitVar_assign_state_call(self)
            else:
                return visitor.visitChildren(self)


    class Var_assign_json_valueContext(Var_assignContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Var_assignContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)
        def EQUALS(self):
            return self.getToken(LSLParser.EQUALS, 0)
        def json_value(self):
            return self.getTypedRuleContext(LSLParser.Json_valueContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterVar_assign_json_value" ):
                listener.enterVar_assign_json_value(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitVar_assign_json_value" ):
                listener.exitVar_assign_json_value(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitVar_assign_json_value" ):
                return visitor.visitVar_assign_json_value(self)
            else:
                return visitor.visitChildren(self)



    def var_assign(self):

        localctx = LSLParser.Var_assignContext(self, self._ctx, self.state)
        self.enterRule(localctx, 30, self.RULE_var_assign)
        try:
            self.state = 151
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,11,self._ctx)
            if la_ == 1:
                localctx = LSLParser.Var_assign_state_callContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 145
                self.match(LSLParser.IDEN)
                self.state = 146
                self.match(LSLParser.EQUALS)
                self.state = 147
                self.state_call()
                pass

            elif la_ == 2:
                localctx = LSLParser.Var_assign_json_valueContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 148
                self.match(LSLParser.IDEN)
                self.state = 149
                self.match(LSLParser.EQUALS)
                self.state = 150
                self.json_value()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_valueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def json_object(self):
            return self.getTypedRuleContext(LSLParser.Json_objectContext,0)


        def json_arr(self):
            return self.getTypedRuleContext(LSLParser.Json_arrContext,0)


        def json_value_lit(self):
            return self.getTypedRuleContext(LSLParser.Json_value_litContext,0)


        def getRuleIndex(self):
            return LSLParser.RULE_json_value

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value" ):
                listener.enterJson_value(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value" ):
                listener.exitJson_value(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value" ):
                return visitor.visitJson_value(self)
            else:
                return visitor.visitChildren(self)




    def json_value(self):

        localctx = LSLParser.Json_valueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_json_value)
        try:
            self.state = 156
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [26]:
                self.enterOuterAlt(localctx, 1)
                self.state = 153
                self.json_object()
                pass
            elif token in [24]:
                self.enterOuterAlt(localctx, 2)
                self.state = 154
                self.json_arr()
                pass
            elif token in [2, 28, 29, 30, 43, 44, 45]:
                self.enterOuterAlt(localctx, 3)
                self.state = 155
                self.json_value_lit()
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


    class Json_objectContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LBRACE(self):
            return self.getToken(LSLParser.LBRACE, 0)

        def json_binding(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.Json_bindingContext)
            else:
                return self.getTypedRuleContext(LSLParser.Json_bindingContext,i)


        def RBRACE(self):
            return self.getToken(LSLParser.RBRACE, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(LSLParser.COMMA)
            else:
                return self.getToken(LSLParser.COMMA, i)

        def getRuleIndex(self):
            return LSLParser.RULE_json_object

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_object" ):
                listener.enterJson_object(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_object" ):
                listener.exitJson_object(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_object" ):
                return visitor.visitJson_object(self)
            else:
                return visitor.visitChildren(self)




    def json_object(self):

        localctx = LSLParser.Json_objectContext(self, self._ctx, self.state)
        self.enterRule(localctx, 34, self.RULE_json_object)
        self._la = 0 # Token type
        try:
            self.state = 171
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,14,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 158
                self.match(LSLParser.LBRACE)
                self.state = 159
                self.json_binding()
                self.state = 164
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==20:
                    self.state = 160
                    self.match(LSLParser.COMMA)
                    self.state = 161
                    self.json_binding()
                    self.state = 166
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 167
                self.match(LSLParser.RBRACE)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 169
                self.match(LSLParser.LBRACE)
                self.state = 170
                self.match(LSLParser.RBRACE)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_bindingContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def COLON(self):
            return self.getToken(LSLParser.COLON, 0)

        def json_value(self):
            return self.getTypedRuleContext(LSLParser.Json_valueContext,0)


        def STRING(self):
            return self.getToken(LSLParser.STRING, 0)

        def IDEN(self):
            return self.getToken(LSLParser.IDEN, 0)

        def getRuleIndex(self):
            return LSLParser.RULE_json_binding

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_binding" ):
                listener.enterJson_binding(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_binding" ):
                listener.exitJson_binding(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_binding" ):
                return visitor.visitJson_binding(self)
            else:
                return visitor.visitChildren(self)




    def json_binding(self):

        localctx = LSLParser.Json_bindingContext(self, self._ctx, self.state)
        self.enterRule(localctx, 36, self.RULE_json_binding)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 173
            _la = self._input.LA(1)
            if not(_la==43 or _la==46):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
            self.state = 174
            self.match(LSLParser.COLON)
            self.state = 175
            self.json_value()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_arrContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LBRACK(self):
            return self.getToken(LSLParser.LBRACK, 0)

        def json_value(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(LSLParser.Json_valueContext)
            else:
                return self.getTypedRuleContext(LSLParser.Json_valueContext,i)


        def RBRACK(self):
            return self.getToken(LSLParser.RBRACK, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(LSLParser.COMMA)
            else:
                return self.getToken(LSLParser.COMMA, i)

        def getRuleIndex(self):
            return LSLParser.RULE_json_arr

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_arr" ):
                listener.enterJson_arr(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_arr" ):
                listener.exitJson_arr(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_arr" ):
                return visitor.visitJson_arr(self)
            else:
                return visitor.visitChildren(self)




    def json_arr(self):

        localctx = LSLParser.Json_arrContext(self, self._ctx, self.state)
        self.enterRule(localctx, 38, self.RULE_json_arr)
        self._la = 0 # Token type
        try:
            self.state = 190
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,16,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 177
                self.match(LSLParser.LBRACK)
                self.state = 178
                self.json_value()
                self.state = 183
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==20:
                    self.state = 179
                    self.match(LSLParser.COMMA)
                    self.state = 180
                    self.json_value()
                    self.state = 185
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 186
                self.match(LSLParser.RBRACK)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 188
                self.match(LSLParser.LBRACK)
                self.state = 189
                self.match(LSLParser.RBRACK)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Json_value_litContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return LSLParser.RULE_json_value_lit

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class Json_value_strContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def STRING(self):
            return self.getToken(LSLParser.STRING, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_str" ):
                listener.enterJson_value_str(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_str" ):
                listener.exitJson_value_str(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_str" ):
                return visitor.visitJson_value_str(self)
            else:
                return visitor.visitChildren(self)


    class Json_value_floatContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NUMBER(self):
            return self.getToken(LSLParser.NUMBER, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_float" ):
                listener.enterJson_value_float(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_float" ):
                listener.exitJson_value_float(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_float" ):
                return visitor.visitJson_value_float(self)
            else:
                return visitor.visitChildren(self)


    class Json_value_intContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def INT(self):
            return self.getToken(LSLParser.INT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_int" ):
                listener.enterJson_value_int(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_int" ):
                listener.exitJson_value_int(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_int" ):
                return visitor.visitJson_value_int(self)
            else:
                return visitor.visitChildren(self)


    class Json_value_nullContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NULL(self):
            return self.getToken(LSLParser.NULL, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_null" ):
                listener.enterJson_value_null(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_null" ):
                listener.exitJson_value_null(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_null" ):
                return visitor.visitJson_value_null(self)
            else:
                return visitor.visitChildren(self)


    class Json_value_jsonataContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def JSONATA(self):
            return self.getToken(LSLParser.JSONATA, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_jsonata" ):
                listener.enterJson_value_jsonata(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_jsonata" ):
                listener.exitJson_value_jsonata(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_jsonata" ):
                return visitor.visitJson_value_jsonata(self)
            else:
                return visitor.visitChildren(self)


    class Json_value_boolContext(Json_value_litContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.Json_value_litContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def TRUE(self):
            return self.getToken(LSLParser.TRUE, 0)
        def FALSE(self):
            return self.getToken(LSLParser.FALSE, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJson_value_bool" ):
                listener.enterJson_value_bool(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJson_value_bool" ):
                listener.exitJson_value_bool(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJson_value_bool" ):
                return visitor.visitJson_value_bool(self)
            else:
                return visitor.visitChildren(self)



    def json_value_lit(self):

        localctx = LSLParser.Json_value_litContext(self, self._ctx, self.state)
        self.enterRule(localctx, 40, self.RULE_json_value_lit)
        self._la = 0 # Token type
        try:
            self.state = 198
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [45]:
                localctx = LSLParser.Json_value_floatContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 192
                self.match(LSLParser.NUMBER)
                pass
            elif token in [44]:
                localctx = LSLParser.Json_value_intContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 193
                self.match(LSLParser.INT)
                pass
            elif token in [28, 29]:
                localctx = LSLParser.Json_value_boolContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 194
                _la = self._input.LA(1)
                if not(_la==28 or _la==29):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                pass
            elif token in [30]:
                localctx = LSLParser.Json_value_nullContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 195
                self.match(LSLParser.NULL)
                pass
            elif token in [43]:
                localctx = LSLParser.Json_value_strContext(self, localctx)
                self.enterOuterAlt(localctx, 5)
                self.state = 196
                self.match(LSLParser.STRING)
                pass
            elif token in [2]:
                localctx = LSLParser.Json_value_jsonataContext(self, localctx)
                self.enterOuterAlt(localctx, 6)
                self.state = 197
                self.match(LSLParser.JSONATA)
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


    class String_or_jsonataContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return LSLParser.RULE_string_or_jsonata

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class String_or_jsonata_jsonataContext(String_or_jsonataContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.String_or_jsonataContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def JSONATA(self):
            return self.getToken(LSLParser.JSONATA, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterString_or_jsonata_jsonata" ):
                listener.enterString_or_jsonata_jsonata(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitString_or_jsonata_jsonata" ):
                listener.exitString_or_jsonata_jsonata(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitString_or_jsonata_jsonata" ):
                return visitor.visitString_or_jsonata_jsonata(self)
            else:
                return visitor.visitChildren(self)


    class String_or_jsonata_stringContext(String_or_jsonataContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a LSLParser.String_or_jsonataContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def STRING(self):
            return self.getToken(LSLParser.STRING, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterString_or_jsonata_string" ):
                listener.enterString_or_jsonata_string(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitString_or_jsonata_string" ):
                listener.exitString_or_jsonata_string(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitString_or_jsonata_string" ):
                return visitor.visitString_or_jsonata_string(self)
            else:
                return visitor.visitChildren(self)



    def string_or_jsonata(self):

        localctx = LSLParser.String_or_jsonataContext(self, self._ctx, self.state)
        self.enterRule(localctx, 42, self.RULE_string_or_jsonata)
        try:
            self.state = 202
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [43]:
                localctx = LSLParser.String_or_jsonata_stringContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 200
                self.match(LSLParser.STRING)
                pass
            elif token in [2]:
                localctx = LSLParser.String_or_jsonata_jsonataContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 201
                self.match(LSLParser.JSONATA)
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


    class Error_nameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ERRORNAMEStatesALL(self):
            return self.getToken(LSLParser.ERRORNAMEStatesALL, 0)

        def ERRORNAMEStatesDataLimitExceeded(self):
            return self.getToken(LSLParser.ERRORNAMEStatesDataLimitExceeded, 0)

        def ERRORNAMEStatesHeartbeatTimeout(self):
            return self.getToken(LSLParser.ERRORNAMEStatesHeartbeatTimeout, 0)

        def ERRORNAMEStatesTimeout(self):
            return self.getToken(LSLParser.ERRORNAMEStatesTimeout, 0)

        def ERRORNAMEStatesTaskFailed(self):
            return self.getToken(LSLParser.ERRORNAMEStatesTaskFailed, 0)

        def ERRORNAMEStatesPermissions(self):
            return self.getToken(LSLParser.ERRORNAMEStatesPermissions, 0)

        def ERRORNAMEStatesResultPathMatchFailure(self):
            return self.getToken(LSLParser.ERRORNAMEStatesResultPathMatchFailure, 0)

        def ERRORNAMEStatesParameterPathFailure(self):
            return self.getToken(LSLParser.ERRORNAMEStatesParameterPathFailure, 0)

        def ERRORNAMEStatesBranchFailed(self):
            return self.getToken(LSLParser.ERRORNAMEStatesBranchFailed, 0)

        def ERRORNAMEStatesNoChoiceMatched(self):
            return self.getToken(LSLParser.ERRORNAMEStatesNoChoiceMatched, 0)

        def ERRORNAMEStatesIntrinsicFailure(self):
            return self.getToken(LSLParser.ERRORNAMEStatesIntrinsicFailure, 0)

        def ERRORNAMEStatesExceedToleratedFailureThreshold(self):
            return self.getToken(LSLParser.ERRORNAMEStatesExceedToleratedFailureThreshold, 0)

        def ERRORNAMEStatesItemReaderFailed(self):
            return self.getToken(LSLParser.ERRORNAMEStatesItemReaderFailed, 0)

        def ERRORNAMEStatesResultWriterFailed(self):
            return self.getToken(LSLParser.ERRORNAMEStatesResultWriterFailed, 0)

        def ERRORNAMEStatesQueryEvaluationError(self):
            return self.getToken(LSLParser.ERRORNAMEStatesQueryEvaluationError, 0)

        def STRING(self):
            return self.getToken(LSLParser.STRING, 0)

        def getRuleIndex(self):
            return LSLParser.RULE_error_name

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterError_name" ):
                listener.enterError_name(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitError_name" ):
                listener.exitError_name(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitError_name" ):
                return visitor.visitError_name(self)
            else:
                return visitor.visitChildren(self)




    def error_name(self):

        localctx = LSLParser.Error_nameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 44, self.RULE_error_name)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 204
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 8796093284344) != 0)):
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





