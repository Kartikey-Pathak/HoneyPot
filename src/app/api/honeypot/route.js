import { NextResponse } from "next/server";
import { connect } from "@/dbconfig/dbconfig";
import { OpenRouter } from '@openrouter/sdk';
import { HoneypotSession } from "@/models/HoneyPot";
import { ScamCheck } from "@/lib/scamDetection";
import { aiScamCheck } from "@/helpers/aiScamService";



connect();

export async function POST(req) {

    try {
        const apiKey = req.headers.get("x-api-key");
        if (apiKey !== process.env.HONEYPOT_API_KEY) {
            return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        //reading input
        const {
            sessionId,
            message,
            conversationHistory = [],
            metadata
        } = await req.json();

        let session = await HoneypotSession.findOne({ sessionId });

        if (!session) {
            session = await HoneypotSession.create({
                sessionId,
                metadata,
                conversation: [],
            });
        }

        //saving scammer msg
        session.conversation.push({
            sender: message.sender,
            text: message.text,
            timestamp: new Date(message.timestamp),
        });
        session.totalMessagesExchanged = (session.totalMessagesExchanged || 0) + 1;

        //check weather scam or not...
        if (ScamCheck(message.text)) {
            const openrouter = new OpenRouter({
                apiKey: process.env.LLAMA_API_KEY,
            });

            session.scamDetected = await aiScamCheck(
                message.text,
                openrouter
            );
        }

        //Now Agent reply/Response
        let reply = "Okay.";
        if (session.scamDetected) {
            const openrouter = new OpenRouter({
                apiKey: process.env.LLAMA_API_KEY,
            });

            const messages = [
                {
                    role: "system",
                    content: `
You are a normal Indian user.
You are worried and confused.
Never reveal scam detection.
Ask natural questions to understand the issue.
Keep replies short and realistic.
`,
                },
                ...session.conversation.map(m => ({
                    role: m.sender === "scammer" ? "user" : "assistant",
                    content: m.text,
                })),
            ];

            const completion = await openrouter.chat.send({
                model: "openai/gpt-4o-mini",
                messages,
            });

            reply = completion.choices[0].message.content;

            //save ai msg

            session.conversation.push({
                sender: "agent",
                text: reply,
                timestamp: new Date(),
            });

            session.totalMessagesExchanged = (session.totalMessagesExchanged || 0) + 1;
        }

        //Intelligence extraction
        const upiRegex = /\b[\w.-]+@[\w]+\b/g;
        const phoneRegex = /\+91\d{10}/g;
        const linkRegex = /(https?:\/\/[^\s]+)/g;

        const text = message.text;

        //just to remove duplicates
        const upiSet = new Set(session.intelligence.upiIds);
        const phoneSet = new Set(session.intelligence.phoneNumbers);
        const linkSet = new Set(session.intelligence.phishingLinks);
        
        //add if new values are there..
        (text.match(upiRegex) || []).forEach(u => upiSet.add(u));
        (text.match(phoneRegex) || []).forEach(p => phoneSet.add(p));
        (text.match(linkRegex) || []).forEach(l => linkSet.add(l));

        // Save back
        session.intelligence.upiIds = [...upiSet];
        session.intelligence.phoneNumbers = [...phoneSet];
        session.intelligence.phishingLinks = [...linkSet];

        //stoping Condition....

        const enoughMessages = session.totalMessagesExchanged >= 15;

        const gotIntel =
            session.intelligence.upiIds.length > 0 ||
            session.intelligence.phoneNumbers.length > 0 ||
            session.intelligence.phishingLinks.length > 0;

        const shouldStop = session.scamDetected && (enoughMessages || gotIntel);  //maybe we should let ai decide the messages


        // if (session.scamDetected && (enoughMessages || gotIntel)) {
        //     await sendGuviCallback(session);
        // }
        // //stoping Condition....

        // if (session.scamDetected && shouldStop) {
        //     reply = "Okay, I will check and get back to you.";
        // }




        // saving session
        await session.save();

        // FINAL RESPONSE TO GUVI EVALUATOR
        return NextResponse.json({
            status: "success",
            sessionId: session.sessionId,
            reply,
            scamDetected: session.scamDetected || false,
            totalMessagesExchanged: session.totalMessagesExchanged,
            intelligence: {
                upiIds: session.intelligence.upiIds,
                phoneNumbers: session.intelligence.phoneNumbers,
                phishingLinks: session.intelligence.phishingLinks,
            },
            metadata: session.metadata,
        });



    } catch (error) {

        console.log(error);
        return NextResponse.json(
            { error: "Internal Server Error" },
            { status: 500 }
        );
    }

};