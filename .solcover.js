module.exports = {
    skipFiles: [
        "test/MockCCIP.sol",
        "test/MockSentinelActions.sol",
        "test/MockUSDC.sol",
        "test/MockWorldID.sol",
    ],
    istanbulReporter: ["text", "lcov", "json-summary"],
    mocha: {
        timeout: 120000,
    },
};
