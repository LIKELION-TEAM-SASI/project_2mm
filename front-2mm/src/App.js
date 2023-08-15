import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./App.css";
import Login from "./pages/Login";
import Passwd from "./pages/Passwd";
import Splash from "./pages/Splash";
import Home from "./pages/Home";
import Membership from "./pages/Membership";
import Membership2 from "./pages/Membership2";
import Membership3 from "./pages/Membership3";
import Membership4 from "./pages/Membership4";
import Post1 from "./pages/Post1";
import Post2 from "./pages/Post2";
import Post3 from "./pages/Post3";
import Schedule1 from "./pages/Schedule1";
import GroupHome from "./pages/GroupHome";
import Album from "./pages/Album";
import ScreenProgress from "./pages/ScreenProgress";
import Screenshare from "./pages/Screenshare";
import GroupDetail from "./pages/GroupDetail";
import Signup1_old from "./pages/Signup1_old";
import Signup2_old from "./pages/Signup2_old";
import Signup3_old from "./pages/Signup3_old";
import Signup1_new from "./pages/Signup1_new";
import Signup2_new from "./pages/Signup2_new";
import Signup3_new from "./pages/Signup3_new";
import Signup4_new from "./pages/Signup4_new";
import Signup5_new from "./pages/Signup5_new";
import Date_List from "./pages/Date_List";
import Date_Plus from "./pages/Date_Plus";
import Date_Write from "./pages/Date_Write";
import AlbumDetail from "./pages/AlbumDetail";
import Post4 from "./pages/Post4";
import AddFamily from "./pages/AddFamily";

function App() {
  return (
    <BrowserRouter>
      <div>
        <Routes>
          <Route path="/" element={<Splash />} />
          <Route path="/Login" element={<Login />} />{" "}
          <Route path="/Passwd" element={<Passwd />} />{" "}
          <Route path="/Home" element={<Home />} />{" "}
          <Route path="/GroupDetail" element={<GroupDetail />} />{" "}
          <Route path="/GroupHome" element={<GroupHome />} />{" "}
          <Route path="/Album" element={<Album />} />{" "}
          <Route path="/Screenshare" element={<Screenshare />} />{" "}
          <Route path="/ScreenProgress" element={<ScreenProgress />} />{" "}
          <Route path="/Passwd" element={<Passwd />} />{" "}
          <Route path="/Membership" element={<Membership />} />{" "}
          <Route path="/Membership2" element={<Membership2 />} />{" "}
          <Route path="/Membership3" element={<Membership3 />} />{" "}
          <Route path="/Membership4" element={<Membership4 />} />{" "}
          <Route path="/Post1" element={<Post1 />} />{" "}
          <Route path="/Post2" element={<Post2 />} />{" "}
          <Route path="/Post3" element={<Post3 />} />{" "}
          <Route path="/Schedule1" element={<Schedule1 />} />{" "}
          <Route path="/Signup1_old" element={<Signup1_old />} />{" "}
          <Route path="/Signup2_old" element={<Signup2_old />} />{" "}
          <Route path="/Signup3_old" element={<Signup3_old />} />{" "}
          <Route path="/Signup1_new" element={<Signup1_new />} />{" "}
          <Route path="/Signup2_new" element={<Signup2_new />} />{" "}
          <Route path="/Signup3_new" element={<Signup3_new />} />{" "}
          <Route path="/Signup4_new" element={<Signup4_new />} />{" "}
          <Route path="/Signup5_new" element={<Signup5_new />} />{" "}
          <Route path="/Date_List" element={<Date_List />} />{" "}
          <Route path="/Date_Plus" element={<Date_Plus />} />{" "}
          <Route path="/AddFamily" element={<AddFamily />} />{" "}
          <Route path="/Date_Write" element={<Date_Write />} />{" "}
          <Route path="/AlbumDetail/:postID" element={<AlbumDetail />} />{" "}
          <Route path="/Post3/:postId" element={<Post3 />} />
          <Route path="/Post4/:postId/:groupCode" element={<Post4 />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
