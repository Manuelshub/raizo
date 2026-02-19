/**
 * @file MockRuntime.ts
 * @notice A minimal, synchronous implementation of the CRE Runtime<T> interface
 * for calling workflow callbacks directly in Mocha tests without the full CRE DON.
 *
 * Usage:
 *   const rt = new MockRuntime(config);
 *   onCronTrigger(rt, {});
 *   expect(rt.reportCalls).to.have.length(1);
 */

export class MockRuntime<T extends object> {
    config: T;
    logs: string[] = [];
    reportCalls: string[] = []; // Captured calldata hex strings

    constructor(config: T) {
        this.config = config;
    }

    log(msg: string): void {
        this.logs.push(msg);
    }

    /**
     * Captures the calldata passed to runtime.report() for assertion.
     * Returns a chainable object with a no-op .result() to match CRE SDK API shape.
     */
    report(req: { calldata?: string; data?: string;[k: string]: unknown }) {
        const calldata = (req.calldata ?? req.data ?? "") as string;
        this.reportCalls.push(calldata);
        return {
            result: () => undefined,
        };
    }

    /**
     * Simulates runInNodeMode by calling the function directly (single-node mode).
     * The aggregator is ignored since we're running in test mode.
     */
    runInNodeMode<R>(fn: (nodeRuntime: MockRuntime<T>) => R, _aggregator: unknown) {
        return () => ({
            result: () => fn(this),
        });
    }

    /** Clears captured state between tests */
    reset(): void {
        this.logs = [];
        this.reportCalls = [];
    }
}
