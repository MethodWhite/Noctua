from typing import List, Callable, Any
from config import NoctuaConfig
from result import NoctuaResult
from core.engine import MWREEngine
from analyzer.universal import NOCTUAAnalyzer


class PipelineStage:
    def __init__(self, name: str, fn: Callable[['PipelineContext'], NoctuaResult]):
        self.name = name
        self.fn = fn


class PipelineContext:
    def __init__(self, path: str, config: NoctuaConfig):
        self.path = path
        self.config = config
        self.engine: MWREEngine = None
        self.results: dict = {}


class Pipeline:
    def __init__(self, config: NoctuaConfig = None):
        self.config = config or NoctuaConfig()
        self.stages: List[PipelineStage] = []

    def register(self, name: str, fn: Callable[['PipelineContext'], NoctuaResult]):
        self.stages.append(PipelineStage(name, fn))

    def run(self, path: str) -> NoctuaResult:
        ctx = PipelineContext(path, self.config)

        for i, stage in enumerate(self.stages):
            if self.config.verbose:
                print(f"[PIPELINE] Stage {i + 1}/{len(self.stages)}: {stage.name}")
            result = stage.fn(ctx)
            if not result.is_ok():
                print(f"[PIPELINE] Stage '{stage.name}' failed: {result}")
                return result

        if self.config.verbose:
            print(f"[PIPELINE] Analysis complete: {len(self.stages)} stages")
        return NoctuaResult.success(ctx.results)


def stage_detect(ctx: PipelineContext) -> NoctuaResult:
    return NoctuaResult.success()


def stage_load(ctx: PipelineContext) -> NoctuaResult:
    try:
        ctx.engine = MWREEngine(ctx.path)
        return NoctuaResult.success()
    except Exception as e:
        return NoctuaResult.error(-1, str(e))


def stage_analyze(ctx: PipelineContext) -> NoctuaResult:
    if not ctx.engine:
        return NoctuaResult.error(-1, "No engine loaded")
    ctx.engine.run()
    return NoctuaResult.success()


def stage_modules(ctx: PipelineContext) -> NoctuaResult:
    if not ctx.engine:
        return NoctuaResult.error(-1, "No engine loaded")
    analyzer = NOCTUAAnalyzer(ctx.engine)
    ctx.results['modules'] = analyzer.run()
    return NoctuaResult.success()


def stage_report(ctx: PipelineContext) -> NoctuaResult:
    if not ctx.engine:
        return NoctuaResult.error(-1, "No engine loaded")
    summary = ctx.engine.run()
    ctx.results['summary'] = summary
    if ctx.config.verbose:
        print(f"\n[+] Analysis complete: {summary}")
    return NoctuaResult.success()
