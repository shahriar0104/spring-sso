import {signIn} from "next-auth/react";

export default function Home() {
  return (
    <div>
      <button onClick={() => signIn("spring-auth")}>Sign in with SpringAuth</button>
    </div>
  )
}
