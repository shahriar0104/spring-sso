import {signIn} from "next-auth/react";

export default function Home() {
  return (
    <div>
      <button onClick={() => signIn("CustomOAuth")}>Sign in with SpringAuth</button>
    </div>
  )
}
