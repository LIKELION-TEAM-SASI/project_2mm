import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useLocation } from "react-router-dom";
import GroupItem from "./GroupItem";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: #f8f8f8;
  border: 1px solid gray;
  margin: 30px auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const BluePoint = styled.div`
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  color: white;
  width: 100%;
`;

const Mark = styled.div`
  position: relative;
  margin-top: -190px;
  left: -150px;
`;

const GroupTitle = styled.div`
  position: relative;
  margin-top: -55px;
  display: inline-block;
  font-family: SUIT;
  font-size: 26px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  z-index: 1;
`;

const BoxZone = styled.div`
  position: relative;
  top: 5px;
  height: 600px;
  margin: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
`;

const Box = styled.div`
  position: relative;
  margin-bottom: 20px;
  width: 340px;
  height: 155px;
  background: url("${BACKEND_URL}/images/whiteblank.svg");
  background-size: cover;
  filter: drop-shadow(5px 5px 5px rgba(0, 0, 0, 0.12));
`;

const CircleImg = styled.div`
  position: relative;
  top: 7px;
`;

const StickyBox = styled.div`
  position: sticky;
  top: 0;
`;
const BtnTitle = styled.div`
  position: relative;
  margin-top: -95px;
  margin-left: 110px;
  margin-bottom: 5px;
  width: 200px;
  color: #3455e0;
  font-family: SUIT;
  font-size: 38px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
`;
const BtnExplain = styled.div`
  position: relative;
  width: 244px;
  margin-left: 110px;
  color: #3455e0;
  font-family: SUIT;
  font-size: 13px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
`;

const GroupHome = () => {
  // 전에 페이지에서 그룹 코드 받아오기
  // const location = useLocation();

  // 이전 페이지에서 전달된 초대코드
  // const { code } = location.state;

  // 게시판, 앨범 등의 구별을 위해 계속 쓸 듯.. 로컬스토리지에 저장해두겠음
  const code = localStorage.getItem("code");
  console.log(code);

  const navigate = useNavigate();

  // 이동 링크 뒤에.. userId같은 거 넘겨줘야하나
  // 게시판 이동
  const gotoBoard = () => {
    navigate("/Post1");
  };
  const gotoAlbum = () => {
    navigate("/Album");
  };
  const gotoScreen = () => {
    navigate("/Screenshare");
  };
  // 일정으로 이동
  const gotoPlan = () => {
    navigate("/Date_List");
  };
  // 홈으로
  const gotoHome = () => {
    navigate("/Home");
  };
  return (
    <Container>
      <StickyBox>
        <BluePoint>
          <img
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
            src={`${BACKEND_URL}/images/bluepoint.svg`}
          />
          <Mark onClick={gotoHome}>
            <img src={`${BACKEND_URL}/images/heartmark.svg`} />
          </Mark>
          <GroupTitle>화목한 우리 가족</GroupTitle>
        </BluePoint>
      </StickyBox>
      <BoxZone>
        <Box>
          <CircleImg>
            <img src={`${BACKEND_URL}/images/boardmark.svg`} />
          </CircleImg>
          <BtnTitle onClick={gotoBoard}>게시판</BtnTitle>
          <BtnExplain>
            가족들과 사진을
            <br />
            공유해보세요.
          </BtnExplain>
        </Box>
        <Box onClick={gotoAlbum}>
          <CircleImg>
            <img src={`${BACKEND_URL}/images/albumimg.svg`} />
          </CircleImg>
          <BtnTitle>앨범</BtnTitle>
          <BtnExplain>
            여기서 사진을 한 눈에
            <br />
            확인할 수 있어요.
          </BtnExplain>
        </Box>
        <Box onClick={gotoScreen}>
          <CircleImg>
            <img src={`${BACKEND_URL}/images/screenmark.svg`} />
          </CircleImg>
          <BtnTitle>화상공유</BtnTitle>
          <BtnExplain>
            핸드폰 사용이 어렵다면
            <br />
            화상공유를 해보세요!
          </BtnExplain>
        </Box>
        <Box onClick={gotoPlan}>
          <CircleImg>
            <img src={`${BACKEND_URL}/images/planmark.svg`} />
          </CircleImg>
          <BtnTitle>일정</BtnTitle>
          <BtnExplain>
            우리 가족 중요 일정을
            <br />
            모아볼 수 있어요.
          </BtnExplain>
        </Box>
      </BoxZone>
    </Container>
  );
};

export default GroupHome;
