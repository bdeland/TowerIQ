let coins = 0;
const SCRIPT_NAME = "DummyCoinSender";

send({
    script: SCRIPT_NAME,
    type: "hook_log",
    timestamp: new Date().getTime,
    payload: {
        event: "script_started",
        message: "DummyCoinSender initialized and sending coin data.",
        script_name: SCRIPT_NAME
    }
});



function sendCoinUpdate() {
    const increment = Math.floor(Math.random() * 101); // Random integer between 0 and 100
    coins += increment;
    // Send as game_metric format with the correct metric name
    const coinMetricMessage = {
        script: SCRIPT_NAME,
        type: "game_metric",
        timestamp: new Date().getTime,
        payload: {
            name: "coins",
            value: coins
        }
    };
    send(coinMetricMessage);
}

// Start sending coin updates every second
const intervalId = setInterval(sendCoinUpdate, 1000);

// Send a status log message about the interval
send({
    script: SCRIPT_NAME,
    type: "hook_log",
    timestamp: new Date().getTime,
    payload: {
        event: "interval_started",
        message: "Coin updates scheduled.",
        script_name: SCRIPT_NAME,
        interval_ms: 1000
    }
});