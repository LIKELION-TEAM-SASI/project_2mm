import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import axios from "axios";
//import KakaoLogin from "react-kakao-login";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

const Container = styled.div`
  position: relative;
  margin: 30px auto;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;
const TextBox1 = styled.div`
  position: relative;
  margin-top: 130px;
  margin-left: 15px;
  color: #0057ff;
  font-family: Tmoney RoundWind;
  font-size: 22px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
`;
const TextBox2 = styled.div`
  position: relative;
  margin-left: 15px;
  color: #0057ff;
  font-family: Tmoney RoundWind;
  font-size: 30px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  z-index: 2;
`;
const CenterZone = styled.div`
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin-top: 437px;
`;
const DesignImg = styled.div`
  position: absolute;
  bottom: 60px;
`;
const LoginBtn = styled.div`
  position: relative;
`;

const Passwd2 = () => {
  const navigate = useNavigate();

  const gotoSignUp = () => {
    navigate("/Membership");
  };
  const gotoLogin = () => {
    navigate("/Login");
  };

  return (
    <Container>
      <TextBox1>모든 준비가 끝났습니다.</TextBox1>
      <TextBox2>2mm를 시작해볼까요?</TextBox2>
      <DesignImg>
        <img
          style={{ width: "100%", height: "100%", objectFit: "cover" }}
          src={`${BACKEND_URL}/images/splashdesign.svg`}
        />
      </DesignImg>
      <CenterZone>
        <LoginBtn onClick={gotoLogin}>
          <img src={`${BACKEND_URL}/images/startbtn.svg`} />
        </LoginBtn>
      </CenterZone>
    </Container>
  );
};

export default Passwd2;
