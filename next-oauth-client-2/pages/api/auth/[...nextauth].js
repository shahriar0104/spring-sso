// pages/api/auth/[...nextauth].js
import NextAuth from "next-auth";

export default NextAuth({
  providers: [
    {
      id: 'custom-oauth',
      name: 'CustomOAuth',
      type: 'oauth',
      version: '2.0',
      scope: 'openid', // or any required scopes
      params: { grant_type: 'authorization_code' },
      issuer: process.env.NEXT_PUBLIC_ISSUER,
      wellKnown: `${process.env.NEXT_PUBLIC_ISSUER}/.well-known/openid-configuration`,
      authorization: 'https://localhost:8080/oauth2/authorize', // Authorization endpoint
      token: 'https://localhost:8080/oauth2/token', // Token endpoint
      userinfo: 'https://localhost:8080/oauth2/userinfo', // User info endpoint
      clientId: process.env.NEXT_AUTH_SPRING_CLIENT_ID,
      clientSecret: process.env.NEXT_AUTH_SPRING_CLIENT_SECRET,
      async profile(profile) {
        return {
          id: profile?.sub,
          name: profile?.aud,
          email: profile?.iss,
          image: profile?.sid,
        };
      },
    },
  ],
  callbacks: {
    async jwt(token, user) {
      if (user) {
        token.accessToken = user.accessToken;
      }
      console.log("token")
      console.log(token)
      return token;
    },
    async session(session, token) {
      session.accessToken = token.accessToken;
      console.log("session")
      console.log(session)
      return session;
    },
  },
});