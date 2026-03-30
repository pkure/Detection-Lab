<h2>Suspicious PowerShell Execution → Network Activity</h2>



<p>
For this scenario, it was assumed the attacker already had access to a Windows workstation (<strong>WS01</strong>). 
Instead of focusing on initial access, the goal here was to simulate what happens next: post-compromise activity, where an attacker starts using PowerShell to download additional tools or extend their foothold.
</p>

<p>
This is a very common real-world pattern. PowerShell is built into Windows, flexible, and heavily abused by attackers.
</p>

<h3>Step 1 - Suspicious PowerShell Execution</h3>

<p>
From WS01, I ran a series of PowerShell commands that mimic typical attacker behavior. These included things like:
</p>

<ul>
  <li>encoded commands (<code>-enc</code>)</li>
  <li>disabling protections (<code>-ep bypass</code>)</li>
  <li>hiding execution (<code>-w hidden</code>)</li>
  <li>download cradle behavior using <code>IEX</code> and <code>Net.WebClient</code></li>
</ul>

<p>
These are command-line arguments, often referred to in detection work as suspicious PowerShell flags. 
They are frequently seen in malicious activity, especially when attackers are trying to obfuscate what they are doing or avoid basic detections.
</p>

<h3>Detection in Splunk (Sysmon)</h3>

<p>
Using Sysmon process creation logs (<code>EventCode=1</code>), I built a detection that looks for combinations of suspicious behavior rather than just one indicator.
</p>

<pre><code>index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 powershell.exe
| eval cmd=lower(CommandLine)
| eval score=0
| eval score=score + if(like(cmd,"% -enc %") OR like(cmd,"% -encodedcommand %"), 2, 0)
| eval score=score + if(like(cmd,"% -nop %") OR like(cmd,"% -noni %"), 1, 0)
| eval score=score + if(like(cmd,"% -w hidden%") OR like(cmd,"% -windowstyle hidden%"), 2, 0)
| eval score=score + if(like(cmd,"% -ep bypass%") OR like(cmd,"% -executionpolicy bypass%"), 2, 0)
| eval score=score + if(like(cmd,"%downloadstring%") OR like(cmd,"%net.webclient%"), 2, 0)
| eval score=score + if(like(cmd,"%invoke-expression%") OR like(cmd,"%iex %"), 2, 0)
| eval score=score + if(like(cmd,"%invoke-webrequest%") OR like(cmd,"%iwr %"), 1, 0)
| eval score=score + if(match(cmd,"[a-z0-9+/=]{40,}"), 2, 0)
| where score &gt;= 3
| table _time host CommandLine ParentProcessName Image score
| sort - score - _time</code></pre>

<h3>Detection Logic</h3>

<p>
Instead of alerting on a single flag like <code>-enc</code>, this detection assigns a score based on multiple suspicious indicators:
</p>

<ul>
  <li>encoded commands</li>
  <li>hidden execution</li>
  <li>execution policy bypass</li>
  <li>download cradle patterns such as <code>IEX</code> and <code>DownloadString</code></li>
  <li>base64-like strings in the command line</li>
</ul>

<p>
This helps reduce noise and makes the detection more realistic. It is looking for behavior, not just a single keyword.
</p>

<h3>Step 2 - Pivot to Network Activity (Zeek)</h3>

<p>
Once the suspicious PowerShell activity was identified, the next step was to answer a simple question:
</p>

<blockquote>
  What did this process actually do on the network?
</blockquote>

<p>
Instead of searching for a known filename from the start, I pivoted based on:
</p>

<ul>
  <li>the affected host (<strong>WS01</strong>)</li>
  <li>the timeframe of the alert</li>
</ul>

<p>
From there, I reviewed Zeek logs, especially <code>conn.log</code> and the related HTTP activity.
</p>

<h3>What Zeek Showed</h3>

<p>
In the same time window, Zeek logs showed outbound connections from WS01 to the attacker system (Parrot).
This included an HTTP request for a remote script:
</p>

<pre><code>/hello.ps1</code></pre>

<p>
That confirmed the PowerShell command was not just suspicious on its face. It was actually being used to retrieve a remote payload.
</p>

<h3>Overall Attack</h3>

<p>
This created a simple but realistic detection pipeline:
</p>

<ol>
  <li><strong>Sysmon Detection</strong> - suspicious PowerShell execution identified based on command-line arguments and behavior</li>
  <li><strong>Investigation Pivot</strong> - analyst pivots on host and timeframe</li>
  <li><strong>Zeek Network Evidence</strong> - HTTP request observed and remote script retrieval confirmed</li>
</ol>

<h3>Real World Impact</h3>

<p>
This scenario is a good example of why combining telemetry sources matters.
</p>

<ul>
  <li>Endpoint logs (Sysmon) tell you that something suspicious happened</li>
  <li>Network logs (Zeek) help confirm what actually occurred</li>
</ul>

<p>
On their own, each source is useful. Together, they tell a much clearer story.
</p>

<h3>Summary</h3>

<p>
This scenario simulates a common post-compromise technique where an attacker uses PowerShell to download additional tools.
By combining Sysmon process creation logs, PowerShell command-line analysis, and Zeek network telemetry, I was able to move from:
</p>

<blockquote>
  “This looks suspicious.”
</blockquote>

<p>
to:
</p>

<blockquote>
  “This host executed a PowerShell download cradle and retrieved a remote script.”
</blockquote>



