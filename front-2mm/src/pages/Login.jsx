import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
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
  left: 150px;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const InputNumber = styled.input`
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

const Login = () => {
  const [phnumber, setPhnumber] = useState("");
  const navigate = useNavigate();

  const gotoPasswd = () => {
    navigate("/Passwd", { state: { phnumber } }); // 다음페이지로 입력한 값 전달
  };

  return (
    <Container>
      <Back>&nbsp;</Back>
      <Title>
        <img src={`${process.env.PUBLIC_URL}/images/logintitle.svg`} />
      </Title>
      <SubTitle>
        <img src={`${process.env.PUBLIC_URL}/images/numbertitle.svg`} />
      </SubTitle>
      {/* 인풋 박스 */}
      <InputNumber
        type="text"
        placeholder="+8210 뒤에 전화번호 8자리를 입력해주세요"
        value={phnumber}
        onChange={(e) => setPhnumber(e.target.value)}
      ></InputNumber>
      <NextBtn onClick={gotoPasswd}>
        <img src={`${process.env.PUBLIC_URL}/images/nextbtn.svg`} />
      </NextBtn>
    </Container>
  );
};

export default Login;
