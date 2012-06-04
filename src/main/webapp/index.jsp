<%
    
    String input = (String)request.getSession().getAttribute("input");
    String output = (String)request.getSession().getAttribute("output");
%>

<html>
<body>
<h2>Picketlink SAML converter</h2>
<form method="GET" action="convert">    
    CONVERTER INPUT: <%= input %><br><br><br>
    CONVERTER OUTPUT:<%= output %><br><br><br>
    <textarea rows="4" cols="200" name="inputToConvert"></textarea><br>
    <input type="submit" name="submit1" value="decode redirect SAML Message" /><br>
    <input type="submit" name="submit1" value="decode post SAML Message" /><br>
    <input type="submit" name="submit1" value="encode redirect SAML Message" /><br>
    <input type="submit" name="submit1" value="encode post SAML Message" /><br>
    <input type="submit" name="submit1" value="format previous decoding output" /><br>
</form>
</body>
</html>
