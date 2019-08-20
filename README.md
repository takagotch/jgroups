### jgroups
---
https://github.com/belaban/JGroups

http://www.jgroups.org/

```java
// src/org/jgroups/auth/sasl/SaslClientContext.java

public class SaslClientContext implements SaslContext {
  private static final byte[] EMPTY_CHALLENGE = new byte[0];
  SaslClient client;
  Subject subject;
  
  public SaslClientContext(final SaslClientFactory saslClientFacotry, final String mech, final String server_name, final CallbackHandler callback_handler, final Map<String, String> props, final Subject subject) throws SaslException {
    this.subject = subject;
    if(this.subject != null) {
      try {
        client = Subject.doAs(this.subject, (PrivilegedExceptionAction<SaslClient>))()
          -> saslClientFactory.createSaslClient(new String[] { mech }, null, SASL.SASL_PROTOCOL_NAME, server_name, props, callback_handler);
      } catch (PrivilegedActionException e) {
        throw (SaslException)e.getCause();
      }
    } else {
      client = saslClientFactory.createSaslClient(new String[] { mech }, null, SASL.SASL_PROTOCOL_NAME, server_name, props, callback_handler);
    }
  }
  
  @Override
  public boolean isSuccessful() {
    return client.isComplete();
  }
  
  @Override
  public boolean needsWrapping() {
    if (client.isComplete()) {
      String qop = (String) client.getNegotiateProperty(Sasl.QOP);
      return (qop != null && (qop.equalsIgnoreCase("auth-int") || qop.equalsIgnoreCase("auth-conf")));
    } else {
      return false;
    }
  }
  
  @Override
  public byte[] wrap() throws SaslException {
    return client.wrap(outgoing, offset, len);
  }
  
  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    return client.unwrap(incoming, offset, len);
  }
  
  @Override
  public Message nextMessage(Address address, SaslHeader header) throws SaslException {
    Message message = new Message(address).setFlag(Message.Flag.OOB);
    return addHeader(message, header.getPayload());
  }
  
  
  private byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
    if (subject != null) {
      try {
        return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>)() -> client.evaluateChallenge(challenge));
      } catch (PrivilegedActionException e) {
        Throwable cause = e.getCause();
        if (cause instanceof SaslException) {
          throw (SaslException)cause;
        } else {
          throw new RuntimeException(cause);
        }
      }
    } else {
      return client.evaluateChallenge(challenge);
    }
  }
}
```

```
```

```
```


