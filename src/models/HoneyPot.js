import mongoose, { Schema } from "mongoose";

const MessageSchema = new Schema({
  sender: {
    type: String,
    enum: ["scammer", "agent"],
    required: true,
  },
  text: {
    type: String,
    required: true,
    trim: true,
  },
  timestamp: {
    type: Date,
    required: true,
  }
});

const IntelligenceSchema = new Schema({
  bankAccounts: [String],
  upiIds: [String],
  phishingLinks: [String],
  phoneNumbers: [String],
  suspiciousKeywords: [String],
});

const HoneypotSessionSchema = new Schema(
  {
    sessionId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    scamDetected: {
      type: Boolean,
      default: false,
    },

    conversation: [MessageSchema],

    intelligence: {
      type: IntelligenceSchema,
      default: () => ({}),  //creates a new empty object every time.
    },

    totalMessagesExchanged: {
      type: Number,
      default: 0,
    },

    agentNotes: {
      type: String,
      default: "",
    },

    callbackSent: {
      type: Boolean,
      default: false,
    },

    metadata: {
      channel: String,
      language: String,
      locale: String,
    },
  },
  { timestamps: true }
);


const HoneypotSession =
  mongoose.models.HoneypotSession ||
  mongoose.model("HoneypotSession", HoneypotSessionSchema);

export { HoneypotSession };
