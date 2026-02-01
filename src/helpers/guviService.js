export async function sendGuviCallback(session) {
    if (session.callbackSent) return;

    try {

        const payload = {
            sessionId: session.sessionId,
            metadata: session.metadata,
            intelligence: session.intelligence,
            totalMessagesExchanged: session.totalMessagesExchanged,
            scamDetected: session.scamDetected,
        };

        const res = await fetch(process.env.GUVI_CALLBACK_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": process.env.GUVI_API_KEY,
            },
            body: JSON.stringify(payload),
        });

        if (!res.ok) {
            throw new Error(`Callback failed: ${res.status}`);
        }


        session.callbackSent = true;
        await session.save();

    } catch (error) {
        console.error("Guvi callback error:", error.message);

    }
}
