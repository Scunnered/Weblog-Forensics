# Weblog forensic tool
In 2020 IT Governance recorded 1,120 violations and cyber-attacks from multiple organisations, accounting for 20.1 billion records, a 64% increase from 2019. Fortunately, the OWASP (The Open Web Application Security Project) publishes yearly Top 10 lists of notable and famous web application security risks based on a consensus among cyber security experts. This was useful for organisations looking to secure web applications during the pandemic. It gives guidelines to mitigate risk and ensure best practices.  

![404-old-owasp](https://user-images.githubusercontent.com/44169316/165753878-433ab804-a1c0-447d-bd96-24dbc89cb69d.png)

OWASP is a non-profit global organisation dedicated to the protection of web-based applications. One of the Open Web Application Security Project is that all their materials should be made publicly available and readily accessible on their website, enabling anybody to improve the security of their online applications. As well as access to their community and content, they also offer tools, videos, and discussion forums. The OWASP Top 10 is one of their best well-known initiatives, if not the most well-known.

It is constantly updated research describing web application security vulnerabilities, focusing on the ten most critical threats. The investigation was carried out in collaboration with a group of security experts worldwide. As the name suggests, an 'awareness document,' according to the Open Web Application Security Project, generates a report on their practices to prevent and mitigate security issues.

Cross-site scripting, SQL Injection, Command Injection, Path Traversal, and unsafe server setup are all examples of security flaws that scanners search for. Scanners are automated programmes that examine online applications for security vulnerabilities such as cross-site scripting, SQL injection, command injection, path traversal, and unsafe server setup. In certain quarters, this category of technologies is referred to as Dynamic Application Security Testing Tools. Several commercial and open-source tools are available for this purpose, each with its pros and downsides. If you are interested in the usefulness of this tool, you may visit the OWASP Benchmark project, which scientifically analyses the performance of several vulnerability detection methods, including DAST.

Websites and online applications are constantly evolving at a fast rate. Every minute, around 380, equating to approximately 252,200 new websites, are created each day globally. Unsafe web development/practices will undoubtedly continue due to the rapid expansion of websites and applications. TalkTalk was attacked by hackers in 2015, resulting in the exposure of over 150,000 customers' personal information as a result of the company's failure to "implement the most basic cyber security procedures" and the company's failure to "implement the most basic cyber security procedures."

Specific online attacks do not need to be complicated; even novice attackers such as 'script kiddies' may exploit vulnerable web applications using easy-to-use exploit kits and web attacks tools, such as those provided by Symantec and Trend Micro.

Exploit kits exploit security flaws in software programmes such as Adobe Reader and Adobe Flash Player by spreading malware such as spyware, viruses, trojans, worms, bots, and backdoors to the target system through buffer overflow scripts or other payloads. Exploit kits spread malware through buffer overflow scripts or other payloads to the target system. Exploit kits provide pre-written exploit code that has already been tested. Web attack tools - Attackers use several standard tools throughout the hacking process, including Metasploit, immunity CANVAS, Hydra, HULK DoS, MPack, and w3af.

This forensic software has been created to to scan .txt weblogs for any vulnerabilities listed above in the OWASP top ten list. This offers a clear indication to the end-user of where security will be lacking in an organisation's infrastructure. The application will not alleviate these worries; instead, it will exhibit suspicious behaviour and the exploit used to infect the system.

![GUI](https://user-images.githubusercontent.com/44169316/165754258-24178f4d-81f0-42fc-8a61-52381f6fa1e4.PNG)

A user will submit a .txt weblog to the program. Once the program receives a weblog to scan, it will cross-reference the uploaded weblog to a database repository of infected weblogs to detect similarities to any applicable OWASP top ten. These infected weblogs will be created in a testing environment and taken from online sources. Once the checks on the newly uploaded weblog have been completed, the program will display the results on the front-end to the user.
![Untitled-1](https://user-images.githubusercontent.com/44169316/165754847-4190c88c-6a9c-4129-a40f-8d7d439ecdc5.png)

A test site had been created in HTML. The site was a mock login page of a fake business. It had a login page and multiple security errors in the code. The site allowed for cross-site request forgery, components with known vulnerabilities, insecure vulnerabilities, and SQL injection. The site was created outside of the virtual machine and then parsed into the virtual machine onto the windows ten iso. Once the site was hosted, applicable attacks were carried out on the test site. The results are then saved as weblogs and stored within the database. The other weblogs are imported from open-source resources to ensure variety and scope, like variation in attack.
![Sequence of events](https://user-images.githubusercontent.com/44169316/165755228-fe61e5b3-43b2-40e3-a25c-36a58ace379a.png)



