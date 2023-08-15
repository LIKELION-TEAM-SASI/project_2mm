import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";

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

const BoxZone = styled.div`
  position: relative;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
`;
const Box = styled.div`
  position: relative;
  width: 375px;
  height: 390px;
  margin-top: 20px;
  margin-bottom: 30px;
`;
const DownloadBtn = styled.button`
  position: relative;
  width: 330px;
  height: 100px;
  background: none;
  border: none;
`;

const AlbumDetail = () => {
  const navigate = useNavigate();

  const gotoBack = () => {
    navigate("/Album");
  };

  // 이전 페이지에서 전달된 초대코드
  const { postID } = useParams();
  console.log(postID);
  const code = localStorage.getItem("code");

  const [post, setPost] = useState(null);
  const [down, setDown] = useState(null);
  const [postLoading, setPostLoading] = useState(true);

  useEffect(() => {
    axios
      .get(`http://127.0.0.1:8000/group/${code}/album/${postID}/`)
      .then((response) => {
        setPost(response.data);
        console.log(response.data);
      });
  }, []);

  // 다운로드
  const onSubmit = () => {
    axios
      .get(`http://127.0.0.1:8000/group/${code}/album/${postID}/download/`, {
        responseType: "blob", // 응답 데이터 Blob 형식으로 설정(지우지마세요)
      })
      .then((res) => {
        // 서버로부터 응답으로 받은 데이터를 Blob 형식으로 다운로드
        const url = window.URL.createObjectURL(res.data);
        const a = document.createElement("a");
        a.href = url;
        a.download = "저장해봄"; // 파일명 설정
        document.body.appendChild(a);
        a.click(); // 링크를 클릭하여 다운로드를 시작

        // 일정 시간 후에 URL을 해제해 메모리 관리
        setTimeout(() => {
          window.URL.revokeObjectURL(url);
        }, 60000);

        a.remove(); // 생성한 링크 엘리먼트를 제거
      })
      .catch((err) => {
        console.error("에러 발생: ", err);
      });
  };

  return (
    <Container>
      <Back onClick={gotoBack}>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} />
      </Back>
      <Title>
        <img src={`${process.env.PUBLIC_URL}/images/albumtitle.svg`} />
      </Title>
      <BoxZone>
        <Box>
          {post && post.image && (
            <img
              style={{ width: "100%", height: "100%", objectFit: "cover" }}
              src={`http://127.0.0.1:8000${post.image}`}
            />
          )}
        </Box>
        {/* 다운로드 버튼 누르면 다운로드 정보 post로 넘겨줘야 함 */}
        <DownloadBtn onClick={onSubmit}>
          <img src={`${process.env.PUBLIC_URL}/images/downbtn.svg`} />
        </DownloadBtn>
      </BoxZone>
    </Container>
  );
};

export default AlbumDetail;
