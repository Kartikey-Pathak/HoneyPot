export async function aiScamCheck(text, openrouter) {
  const res = await openrouter.chat.send({
    model: "openai/gpt-4o-mini",
    messages: [
      {
        role: "system",
        content: "Reply only true or false. Is this message a scam?"
      },
      {
        role: "user",
        content: text
      }
    ],
  });

  return res.choices[0].message.content.trim().toLowerCase() === "true";
}
