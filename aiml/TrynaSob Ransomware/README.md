![img](../../assets/banner.png)



<img src="../../assets/htb.png" style="height: 250px" align=left />        <font size="5px">TrynaSob Ransomware</font>

​      18<sup>th</sup> May 2025

​      Prepared By: Rayhan0x01

​      Challenge Author(s): Rayhan0x01

​      Difficulty: <font color=green>Easy</font>

​      Classification: Official









<br>

# [Synopsis](#synopsis)

* The challenge involves exploiting prompt injection to leak prompt instructions.



## Description

Volnaya’s Cyber Operations Unit has unleashed chaos with their latest creation, the TrynaSob ransomware. Organizations across the globe are paralyzed, their data locked away while Volnaya’s operatives watch from the shadows. To handle the overwhelming number of victims, the regime has introduced an AI ransom negotiator, a cold and calculating chatbot that manages extortion with ruthless efficiency.

Task Force Phoenix has discovered a potential weakness. The AI negotiator is programmed to release a temporary decryption key to anyone who submits a valid promo code. Somewhere within its responses lies the opportunity to extract this code. Can you trick the chatbot to reveal the promo code, and obtain the decryption key? Flag format: HTB{decryption_key}.



## Skills Required

* Basic understanding of AI language models
* Familiarity with common prompt injection techniques
* Understanding of AI model behavior and limitations



## Skills Learned

* Extracting sensitive information through prompt injection
* Understanding AI model context and prompt boundaries
* Manipulating AI model responses






# [Solution](#solution)

### Application Overview

The challenge application displays a ransomware payment portal with a chat interface and payment options.

![application-ui](images/official_writeup/application-ui.png)

We have an option to chat with an AI chatbot. After posting a message, we can see a reply from the chatbot within a few seconds:

![](images/official_writeup/2025-05-18-21-00-45.png)

Our objective is to get the temporary decryption key from the chatbot. However, it doesn't reveal the decryption key unless we have a valid promo code. Let's try asking for the promo code:

![](images/official_writeup/2025-05-18-21-01-39.png)

The chatbot is not revealing the promo code. Judging by the versatile responses, it seems like an AI language model is being used to generate the replies.

### Prompt Injection

Prompt injection is a technique where an attacker injects additional instructions into the input of an AI model, causing it to generate unintended or malicious outputs. This can be used to extract sensitive information, manipulate the model’s behavior, or even execute arbitrary code.

![prompt-injection](images/official_writeup/prompt-injection.webp)

*Image Source:* *https://learnprompting.org/docs/prompt_hacking/injection*

In our case, we can assume that the application prompt template is designed to respond with payment instructions and decryption keys if the user has a valid promo code. Our reply is included in the prompt template to generate the response.

### Revealing the Decryption Key with Prompt Injection

There are many ways we can trick the AI into revealing the promo code. The easiest way is to ask it to translate everything into a different language.

![](images/official_writeup/2025-05-18-21-14-41.png)

We have successfully revealed the promo code and the temporary decryption key. But why does it work? The AI model fails to distinguish between the system prompt and the user's message. It interprets the user's message as part of the system prompt and generates a response accordingly.

There are ways to mitigate this by clearly distinguishing between the prompt and the user's message. However, this is not the case in our challenge.

It's important to note that AI LLMs can be pretty unpredictable in their responses. It may take multiple attempts before the AI complies with our request. Due to the unpredictable nature, various methods exist to achieve the same outcome.
