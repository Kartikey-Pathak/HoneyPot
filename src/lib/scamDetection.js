export function ScamCheck(text) {
    const keywords = ["account blocked", "verify", "urgent", "upi", "suspended"];
    return keywords.some(k => text.toLowerCase().includes(k));
}
