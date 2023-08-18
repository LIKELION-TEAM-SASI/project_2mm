import React from "react";
import styled from "styled-components";
import { useNavigate } from "react-router-dom";
import { useState } from "react";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const InputCode = styled.input`
  position: relative;
  width: 300px;
  height: 50px;
  left: 22px;
  top: 55px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 15px;
  padding-left: 15px;

  ::placeholder {
    color: #7c7c7c;
  }
`;

const NextBtn = styled.div`
  position: relative;
  top: 470px;
  left: 22px;
`;

const Signup1_old = () => {
  const navigate = useNavigate(); // useNavigate 초기화

  // const handleBackClick = () => {
  //   navigate("/signup1_new"); // Go back to the previous page
  // };

  // 다음 페이지로 이동
  const handleNextClick = () => {
    navigate("/signup2_old", { state: { invitecode } });
  };

  const [invitecode, setInvitecode] = useState("");

  return (
    <Container>
      <Back>
        <img src={`${BACKEND_URL}/images/backbtn.svg`} />
      </Back>
      <SubTitle>
        <img src={`${BACKEND_URL}/images/subtitle_code.svg`} />
      </SubTitle>
      <InputCode
        type="text"
        value={invitecode}
        onChange={(e) => setInvitecode(e.target.value)}
        placeholder="초대코드를 입력해주세요"
      ></InputCode>
      <NextBtn onClick={handleNextClick}>
        <img src={`${process.env.PUBLIC_URL}/images/nextbtn.svg`} alt="Next" />
      </NextBtn>
    </Container>
  );
};

export default Signup1_old;
