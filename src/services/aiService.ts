import { GoogleGenerativeAI } from "@google/generative-ai";

const apiKey = process.env.GEMINI_API_KEY || "";
const genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null;
const model = genAI ? genAI.getGenerativeModel({ model: "gemini-1.5-flash" }) : null;

export async function analyzeCallContext(metadata: any) {
  if (!model) {
    return { intent: 'unknown', rationale: 'AI Service unconfigured', aiConfidence: 0 };
  }
  try {
    const prompt = `
      Analyze this telecom SIP metadata and classify the call intent and risk.
      Metadata: ${JSON.stringify(metadata)}
      
      Respond in JSON format with:
      {
        "intent": "financial" | "delivery" | "personal" | "scam" | "unknown",
        "rationale": "short explanation",
        "aiConfidence": 0.0 to 1.0
      }
    `;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    // Simple JSON extraction
    const match = text.match(/\{.*\}/s);
    return match ? JSON.parse(match[0]) : { intent: 'unknown', rationale: 'Analysis failed', aiConfidence: 0 };
  } catch (error) {
    console.error("AI Analysis error:", error);
    return { intent: 'unknown', rationale: 'Network timeout', aiConfidence: 0 };
  }
}
