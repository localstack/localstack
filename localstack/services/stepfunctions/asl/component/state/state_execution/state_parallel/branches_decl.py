from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.count_down_latch import CountDownLatch
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.program_worker import ProgramWorker


class BranchesDecl(EvalComponent):
    def __init__(self, programs: list[Program]):
        self.programs: Final[list[Program]] = programs

    def _eval_body(self, env: Environment) -> None:
        # CountDownLatch to detect halting of all worker threads.
        latch: Final[CountDownLatch] = CountDownLatch(len(self.programs))

        # Input value for every state_parallel process.
        input_val = env.stack.pop()

        worker_pool: list[ProgramWorker] = list()
        for program in self.programs:
            # Environment frame for this sub process.
            env_frame: Environment = env.open_frame()
            env_frame.inp = input_val

            # Launch the worker.
            worker = ProgramWorker()
            worker.eval(program=program, env_frame=env_frame, latch=latch)

            worker_pool.append(worker)

        latch.wait()

        result_list = list()

        for worker in reversed(worker_pool):
            env_frame = worker.env_frame
            result_list.append(env_frame.inp)
            env.close_frame(env_frame)

        env.stack.append(result_list)
