import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useEffect } from "react";
import axios from "axios";
// 수정함!!

const Container = styled.div`
  position: relative;
  margin: 30px auto;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 1rem;
    padding-right: 1rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 165px;
`;

const PicZone = styled.div`
  position: relative;
  max-width: 360px;
  height: 650px;
  margin: auto;
  overflow-y: scroll;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
  //   display: flex;
  //   flex-direction: column;
  //   justify-content: center;
  //   align-items: center;
`;
const PicBox = styled.div`
  position: relative;
  margin-left: 10px;
  margin-bottom: 5px;
  display: inline-block;
`;

// 앨범 하나하나 컴포넌트
const AlbumItem = ({ postID, postImage }) => {
  const navigate = useNavigate();

  const goAlbumDetail = () => {
    navigate(`/AlbumDetail/${postID}`);
  };
  return (
    <>
      <PicBox onClick={goAlbumDetail}>
        {" "}
        <img
          style={{
            width: "165px",
            height: "165px",
            borderRadius: "6px",
            objectFit: "cover",
          }}
          src={`http://127.0.0.1:8000${postImage}`}
        />
      </PicBox>
    </>
  );
};
const Album = () => {
  const navigate = useNavigate();

  const gotoBack = () => {
    navigate("/GroupHome");
  };

  const [postList, setPostList] = useState([]);
  const [loading, setLoading] = useState(false);
  const code = localStorage.getItem("code");

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        // API 호출
        const response = await axios.get(
          `http://127.0.0.1:8000/group/${code}/album/`
        );
        setPostList(response.data); // API 응답으로 받은 데이터를 state에 저장
        // user_id 로그인하고 전달받기
      } catch (error) {
        console.error("Error fetching data:", error);
      }
      setLoading(false); // 로딩 상태 변경
    };
    fetchData(); // useEffect에서 fetchData 함수 호출
  }, []);

  if (loading) {
    return <div>대기중...</div>;
  }

  return (
    <Container>
      <Back onClick={gotoBack}>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} />
      </Back>
      <Title>
        <img src={`${process.env.PUBLIC_URL}/images/albumtitle.svg`} />
      </Title>
      <PicZone>
        {postList.map((e) => (
          <AlbumItem key={e.id} postID={e.id} postImage={e.image}>
            {/* <img
              src={post && post.image}
              style={{ display: "block", width: "170px", height: "170px" }}
            /> */}
          </AlbumItem>
        ))}
      </PicZone>
    </Container>
  );
};

export default Album;
