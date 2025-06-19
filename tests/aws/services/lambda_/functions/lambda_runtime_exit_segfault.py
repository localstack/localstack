import sys

# Triggers segfault through a stack overflow when using unbound recursion:
# https://stackoverflow.com/questions/61031604/why-am-i-getting-a-segmentation-fault-using-python3#comment107974230_61031712
# This number should be sufficiently low to trigger a runtime exception, otherwise Lambda in AWS ends up timing out before a SEGFAULT is sent.
sys.setrecursionlimit(10_000)


# Unbound recursion: https://code-maven.com/slides/python/unbound-recursion
def recursion(n):
    print(f"In recursion {n}")
    recursion(n + 1)


recursion(1)
